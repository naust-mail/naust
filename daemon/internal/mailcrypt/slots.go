package mailcrypt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"naust/daemon/internal/store/ent"
	entmailkeyslot "naust/daemon/internal/store/ent/mailkeyslot"
	entuser "naust/daemon/internal/store/ent/user"
)

// Slot type names as stored in the database. These appear in AAD, so
// they are part of the crypto contract and must never be renamed.
const (
	SlotPassword     = "password"
	SlotRecoveryCode = "recovery_code"
	SlotPasskeyPRF   = "passkey_prf"
)

// ErrNoSlot distinguishes "encryption not set up" from "wrong secret".
var ErrNoSlot = errors.New("no such key slot")

// ErrWrongSecret is returned when a supplied password, recovery code,
// or PRF output does not unwrap any matching slot.
var ErrWrongSecret = errors.New("secret did not unlock the encryption key")

// PreparedSlot is a wrapped-but-uncommitted slot. Setup and rotation
// ceremonies build these, park them in an EncryptionSetup row, and
// only persist them as MailKeySlot rows once the user proves they
// copied a recovery code. JSON-serializable for that parking.
type PreparedSlot struct {
	SlotType   string `json:"slot_type"`
	Label      string `json:"label"`
	Version    int    `json:"version"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	KDFSalt    []byte `json:"kdf_salt"`
}

// EncodePrepared serializes prepared slots for an EncryptionSetup row.
func EncodePrepared(slots []PreparedSlot) (string, error) {
	b, err := json.Marshal(slots)
	return string(b), err
}

// DecodePrepared reverses EncodePrepared.
func DecodePrepared(s string) ([]PreparedSlot, error) {
	var slots []PreparedSlot
	if err := json.Unmarshal([]byte(s), &slots); err != nil {
		return nil, err
	}
	return slots, nil
}

// BuildPasswordSlot wraps the root key under the login password.
func BuildPasswordSlot(userID int, password string, rootKey []byte) (PreparedSlot, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return PreparedSlot{}, err
	}
	wk := DeriveKeyFromPassword(password, salt)
	ct, nonce, err := Wrap(rootKey, wk, userID, SlotPassword, "", SlotVersion)
	if err != nil {
		return PreparedSlot{}, err
	}
	return PreparedSlot{SlotType: SlotPassword, Version: SlotVersion, WrappedKey: ct, Nonce: nonce, KDFSalt: salt}, nil
}

// BuildRecoverySlots wraps the root key under each recovery code,
// labelled "0".."N-1".
func BuildRecoverySlots(userID int, codes []string, rootKey []byte) ([]PreparedSlot, error) {
	slots := make([]PreparedSlot, 0, len(codes))
	for i, code := range codes {
		label := fmt.Sprintf("%d", i)
		secret := []byte(NormalizeRecoveryCode(code))
		salt, err := GenerateSalt()
		if err != nil {
			return nil, err
		}
		wk, err := DeriveKeyFromSecret(secret, salt)
		if err != nil {
			return nil, err
		}
		ct, nonce, err := Wrap(rootKey, wk, userID, SlotRecoveryCode, label, SlotVersion)
		if err != nil {
			return nil, err
		}
		slots = append(slots, PreparedSlot{SlotType: SlotRecoveryCode, Label: label, Version: SlotVersion, WrappedKey: ct, Nonce: nonce, KDFSalt: salt})
	}
	return slots, nil
}

// BuildPRFSlot wraps the root key under a WebAuthn PRF output. The
// label is the credential ID; prfSalt (the eval salt sent to the
// authenticator) is stored on the slot so future assertions can
// reproduce the same PRF output.
func BuildPRFSlot(userID int, credentialID string, prfOutput, prfSalt, rootKey []byte) (PreparedSlot, []byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return PreparedSlot{}, nil, err
	}
	wk, err := DeriveKeyFromSecret(prfOutput, salt)
	if err != nil {
		return PreparedSlot{}, nil, err
	}
	ct, nonce, err := Wrap(rootKey, wk, userID, SlotPasskeyPRF, credentialID, SlotVersion)
	if err != nil {
		return PreparedSlot{}, nil, err
	}
	return PreparedSlot{SlotType: SlotPasskeyPRF, Label: credentialID, Version: SlotVersion, WrappedKey: ct, Nonce: nonce, KDFSalt: salt}, prfSalt, nil
}

// UnwrapPreparedRecovery unwraps the root key from a prepared
// recovery slot, verifying the code in the process. Used by the setup
// and rotation challenges before anything is committed.
func UnwrapPreparedRecovery(userID int, slot PreparedSlot, code string) ([]byte, error) {
	secret := []byte(NormalizeRecoveryCode(code))
	wk, err := DeriveKeyFromSecret(secret, slot.KDFSalt)
	if err != nil {
		return nil, err
	}
	root, err := Unwrap(slot.WrappedKey, slot.Nonce, wk, userID, slot.SlotType, slot.Label, slot.Version)
	if err != nil {
		return nil, ErrWrongSecret
	}
	return root, nil
}

// InsertSlots persists prepared slots for a user. tx may be a
// transactional client.
func InsertSlots(ctx context.Context, tx *ent.Client, userID int, slots []PreparedSlot) error {
	builders := make([]*ent.MailKeySlotCreate, 0, len(slots))
	for _, s := range slots {
		b := tx.MailKeySlot.Create().
			SetUserID(userID).
			SetSlotType(entmailkeyslot.SlotType(s.SlotType)).
			SetLabel(s.Label).
			SetVersion(s.Version).
			SetWrappedKey(s.WrappedKey).
			SetNonce(s.Nonce).
			SetKdfSalt(s.KDFSalt)
		builders = append(builders, b)
	}
	return tx.MailKeySlot.CreateBulk(builders...).Exec(ctx)
}

// SlotTypes returns the distinct committed slot types for a user.
func SlotTypes(ctx context.Context, store *ent.Client, userID int) ([]string, error) {
	var types []string
	err := store.MailKeySlot.Query().
		Where(entmailkeyslot.HasUserWith(entuser.ID(userID))).
		Select(entmailkeyslot.FieldSlotType).
		GroupBy(entmailkeyslot.FieldSlotType).
		Scan(ctx, &types)
	return types, err
}

// HasSlot reports whether the user has a committed slot of the type.
func HasSlot(ctx context.Context, store *ent.Client, userID int, slotType string) (bool, error) {
	return store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotType(slotType)),
		).
		Exist(ctx)
}

// UnwrapViaPassword unwraps the root key with the user's password
// slot. Returns ErrNoSlot when encryption is not enabled and
// ErrWrongSecret when the password does not unlock it.
func UnwrapViaPassword(ctx context.Context, store *ent.Client, userID int, password string) ([]byte, error) {
	slot, err := store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePassword),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNoSlot
	}
	if err != nil {
		return nil, err
	}
	wk := DeriveKeyFromPassword(password, slot.KdfSalt)
	root, err := Unwrap(slot.WrappedKey, slot.Nonce, wk, userID, string(slot.SlotType), slot.Label, slot.Version)
	if err != nil {
		return nil, ErrWrongSecret
	}
	return root, nil
}

// UnwrapViaRecoveryCode tries each recovery slot until one unwraps.
func UnwrapViaRecoveryCode(ctx context.Context, store *ent.Client, userID int, code string) ([]byte, error) {
	slots, err := store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypeRecoveryCode),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(slots) == 0 {
		return nil, ErrNoSlot
	}
	secret := []byte(NormalizeRecoveryCode(code))
	for _, slot := range slots {
		wk, err := DeriveKeyFromSecret(secret, slot.KdfSalt)
		if err != nil {
			return nil, err
		}
		root, err := Unwrap(slot.WrappedKey, slot.Nonce, wk, userID, string(slot.SlotType), slot.Label, slot.Version)
		if err == nil {
			return root, nil
		}
	}
	return nil, ErrWrongSecret
}

// UnwrapViaPRF unwraps the root key with the PRF slot belonging to
// one credential.
func UnwrapViaPRF(ctx context.Context, store *ent.Client, userID int, credentialID string, prfOutput []byte) ([]byte, error) {
	slot, err := store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePasskeyPrf),
			entmailkeyslot.LabelEQ(credentialID),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNoSlot
	}
	if err != nil {
		return nil, err
	}
	wk, err := DeriveKeyFromSecret(prfOutput, slot.KdfSalt)
	if err != nil {
		return nil, err
	}
	root, err := Unwrap(slot.WrappedKey, slot.Nonce, wk, userID, string(slot.SlotType), slot.Label, slot.Version)
	if err != nil {
		return nil, ErrWrongSecret
	}
	return root, nil
}

// PRFSlots returns every passkey_prf slot for a user (label =
// credential ID, PrfSalt = the stored eval salt).
func PRFSlots(ctx context.Context, store *ent.Client, userID int) ([]*ent.MailKeySlot, error) {
	return store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePasskeyPrf),
		).
		All(ctx)
}

// PRFSaltFor returns the stored eval salt for a credential's PRF slot.
func PRFSaltFor(ctx context.Context, store *ent.Client, userID int, credentialID string) ([]byte, error) {
	slot, err := store.MailKeySlot.Query().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePasskeyPrf),
			entmailkeyslot.LabelEQ(credentialID),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNoSlot
	}
	if err != nil {
		return nil, err
	}
	return slot.PrfSalt, nil
}

// ReplacePasswordSlot swaps the password slot for one wrapped under
// newPassword, given the already-unwrapped root key. Runs in a
// transaction: delete plus insert is atomic.
func ReplacePasswordSlot(ctx context.Context, store *ent.Client, userID int, newPassword string, rootKey []byte) error {
	slot, err := BuildPasswordSlot(userID, newPassword, rootKey)
	if err != nil {
		return err
	}
	return withTx(ctx, store, func(tx *ent.Client) error {
		if _, err := tx.MailKeySlot.Delete().
			Where(
				entmailkeyslot.HasUserWith(entuser.ID(userID)),
				entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePassword),
			).
			Exec(ctx); err != nil {
			return err
		}
		return InsertSlots(ctx, tx, userID, []PreparedSlot{slot})
	})
}

// ReplaceRecoverySlots atomically swaps all recovery slots for a
// prepared set. Used when a rotation challenge passes.
func ReplaceRecoverySlots(ctx context.Context, store *ent.Client, userID int, slots []PreparedSlot) error {
	return withTx(ctx, store, func(tx *ent.Client) error {
		if _, err := tx.MailKeySlot.Delete().
			Where(
				entmailkeyslot.HasUserWith(entuser.ID(userID)),
				entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypeRecoveryCode),
			).
			Exec(ctx); err != nil {
			return err
		}
		return InsertSlots(ctx, tx, userID, slots)
	})
}

// InsertPRFSlot persists a prepared PRF slot with its eval salt,
// replacing any existing slot for the same credential.
func InsertPRFSlot(ctx context.Context, store *ent.Client, userID int, slot PreparedSlot, prfSalt []byte) error {
	return withTx(ctx, store, func(tx *ent.Client) error {
		if _, err := tx.MailKeySlot.Delete().
			Where(
				entmailkeyslot.HasUserWith(entuser.ID(userID)),
				entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePasskeyPrf),
				entmailkeyslot.LabelEQ(slot.Label),
			).
			Exec(ctx); err != nil {
			return err
		}
		return tx.MailKeySlot.Create().
			SetUserID(userID).
			SetSlotType(entmailkeyslot.SlotTypePasskeyPrf).
			SetLabel(slot.Label).
			SetVersion(slot.Version).
			SetWrappedKey(slot.WrappedKey).
			SetNonce(slot.Nonce).
			SetKdfSalt(slot.KDFSalt).
			SetPrfSalt(prfSalt).
			Exec(ctx)
	})
}

// DeletePRFSlot removes the PRF slot for a credential (called when
// the WebAuthn credential itself is deleted). Missing slot is not an
// error.
func DeletePRFSlot(ctx context.Context, store *ent.Client, userID int, credentialID string) error {
	_, err := store.MailKeySlot.Delete().
		Where(
			entmailkeyslot.HasUserWith(entuser.ID(userID)),
			entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePasskeyPrf),
			entmailkeyslot.LabelEQ(credentialID),
		).
		Exec(ctx)
	return err
}

func withTx(ctx context.Context, store *ent.Client, fn func(tx *ent.Client) error) error {
	tx, err := store.Tx(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx.Client()); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// EncodeCredentialID renders a WebAuthn credential ID as the slot
// label form used everywhere in this package.
func EncodeCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}
