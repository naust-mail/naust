package httpapi

import (
	"encoding/json"
	"testing"

	"naust/daemon/internal/api"
)

func TestUserCRUD(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// Create.
	w := doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email:      "bob@example.com",
		Password:   "a valid password",
		QuotaBytes: 1 << 30,
	})
	if w.Code != 201 {
		t.Fatalf("create status = %d, body %s", w.Code, w.Body)
	}

	// List: seeded admin + bob, ordered by email.
	w = doJSON(t, s, "GET", "/api/users", token, nil)
	var list api.UsersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Users) != 2 || list.Users[1].Email != "bob@example.com" || list.Users[1].Role != "user" {
		t.Fatalf("list = %+v", list.Users)
	}

	// Update quota only; role untouched.
	newQuota := int64(2 << 30)
	w = doJSON(t, s, "PATCH", "/api/users/bob@example.com", token, api.UpdateUserRequest{QuotaBytes: &newQuota})
	if w.Code != 200 {
		t.Fatalf("update status = %d, body %s", w.Code, w.Body)
	}
	var updated api.User
	json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.QuotaBytes != newQuota || updated.Role != "user" {
		t.Errorf("after update: %+v", updated)
	}

	// Password change: new password must log in.
	w = doJSON(t, s, "PUT", "/api/users/bob@example.com/password", token, api.SetPasswordRequest{Password: "another password"})
	if w.Code != 204 {
		t.Fatalf("set password status = %d", w.Code)
	}
	w = doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: "bob@example.com", Password: "another password"})
	if w.Code != 200 {
		t.Errorf("login with new password: status = %d", w.Code)
	}

	// Delete.
	if w = doJSON(t, s, "DELETE", "/api/users/bob@example.com", token, nil); w.Code != 204 {
		t.Fatalf("delete status = %d", w.Code)
	}
	if w = doJSON(t, s, "DELETE", "/api/users/bob@example.com", token, nil); w.Code != 404 {
		t.Errorf("re-delete status = %d, want 404", w.Code)
	}
}

func TestCreateUserRejections(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	for name, req := range map[string]api.CreateUserRequest{
		"uppercase email":  {Email: "Bob@example.com", Password: "a valid password"},
		"no domain":        {Email: "bob", Password: "a valid password"},
		"slash in local":   {Email: "b/ob@example.com", Password: "a valid password"},
		"short password":   {Email: "bob@example.com", Password: "short"},
		"dcv address":      {Email: "postmaster@example.com", Password: "a valid password"},
		"dcv plus address": {Email: "admin+x@example.com", Password: "a valid password"},
		"bad role":         {Email: "bob@example.com", Password: "a valid password", Role: "root"},
		"negative quota":   {Email: "bob@example.com", Password: "a valid password", QuotaBytes: -1},
	} {
		if w := doJSON(t, s, "POST", "/api/users", token, req); w.Code != 400 {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}

	// Duplicate email is a conflict, not a 400. (The seeded admin can't
	// be used here: admin@ is a DCV address and fails earlier.)
	ok := api.CreateUserRequest{Email: "bob@example.com", Password: "a valid password"}
	if w := doJSON(t, s, "POST", "/api/users", token, ok); w.Code != 201 {
		t.Fatalf("create: status = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/users", token, ok); w.Code != 409 {
		t.Errorf("duplicate: status = %d, want 409", w.Code)
	}
}

func TestLastAdminGuards(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	demote := "user"
	if w := doJSON(t, s, "PATCH", "/api/users/admin@example.com", token, api.UpdateUserRequest{Role: &demote}); w.Code != 400 {
		t.Errorf("demote last admin: status = %d, want 400", w.Code)
	}
	if w := doJSON(t, s, "DELETE", "/api/users/admin@example.com", token, nil); w.Code != 400 {
		t.Errorf("delete last admin: status = %d, want 400", w.Code)
	}

	// With a second admin present, both operations are allowed.
	w := doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email: "admin2@example.com", Password: "a valid password", Role: "admin",
	})
	if w.Code != 201 {
		t.Fatalf("create second admin: status = %d", w.Code)
	}
	if w = doJSON(t, s, "PATCH", "/api/users/admin2@example.com", token, api.UpdateUserRequest{Role: &demote}); w.Code != 200 {
		t.Errorf("demote second admin: status = %d, body %s", w.Code, w.Body)
	}
}

func TestDemotedAdminLosesSessionsImmediately(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email: "admin2@example.com", Password: "a valid password", Role: "admin",
	})
	if w.Code != 201 {
		t.Fatal("create second admin failed")
	}
	second := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: "admin2@example.com", Password: "a valid password"})
	var secondLogin api.LoginResponse
	json.Unmarshal(second.Body.Bytes(), &secondLogin)

	demote := "user"
	if w = doJSON(t, s, "PATCH", "/api/users/admin2@example.com", token, api.UpdateUserRequest{Role: &demote}); w.Code != 200 {
		t.Fatalf("demote status = %d", w.Code)
	}
	if w = doJSON(t, s, "GET", "/api/auth/me", secondLogin.Token, nil); w.Code != 401 {
		t.Errorf("demoted admin session still alive: status = %d, want 401", w.Code)
	}
}

func TestNonAdminCannotManageUsers(t *testing.T) {
	s, _ := newTestServer(t)
	admin := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/users", admin, api.CreateUserRequest{
		Email: "bob@example.com", Password: "a valid password",
	})
	if w.Code != 201 {
		t.Fatal("create user failed")
	}
	resp := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: "bob@example.com", Password: "a valid password"})
	var bob api.LoginResponse
	json.Unmarshal(resp.Body.Bytes(), &bob)

	if w = doJSON(t, s, "GET", "/api/users", bob.Token, nil); w.Code != 403 {
		t.Errorf("non-admin list users: status = %d, want 403", w.Code)
	}
	if w = doJSON(t, s, "GET", "/api/aliases", bob.Token, nil); w.Code != 403 {
		t.Errorf("non-admin list aliases: status = %d, want 403", w.Code)
	}
}
