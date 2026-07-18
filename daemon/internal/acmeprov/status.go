package acmeprov

import (
	"context"
	"path/filepath"
	"time"

	"naust/daemon/internal/sslcert"
	"naust/daemon/internal/webapply"
)

// CertState classifies the on-disk certificate of one domain.
type CertState string

const (
	CertValid      CertState = "valid"
	CertExpiring   CertState = "expiring" // valid but inside the renewal window
	CertExpired    CertState = "expired"  // also covers not-yet-valid
	CertSelfSigned CertState = "self-signed"
	CertMissing    CertState = "missing"
)

// DomainStatus is the certificate state of one hosted domain.
type DomainStatus struct {
	Domain   string
	Cert     CertState
	NotAfter time.Time // zero when no certificate is installed
}

// DomainStatuses lists every domain the web tier serves with its
// on-disk certificate state. It only reads the store and the ssl
// directory; no CA or DNS traffic.
func (p *Provisioner) DomainStatuses(ctx context.Context) ([]DomainStatus, error) {
	in, err := webapply.LoadInput(ctx, p.Store, p.PrimaryHostname, p.PublicIP, p.PublicIPv6)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	certs, err := sslcert.Scan(filepath.Join(p.StorageRoot, "ssl"), p.PrimaryHostname, now)
	if err != nil {
		return nil, err
	}
	var out []DomainStatus
	for _, site := range webapply.Derive(in) {
		ds := DomainStatus{Domain: site.Domain, Cert: CertMissing}
		if pair, ok := certs[site.Domain]; ok {
			ds.NotAfter = pair.NotAfter
			switch {
			case pair.SelfSigned:
				ds.Cert = CertSelfSigned
			case !pair.Valid(now):
				ds.Cert = CertExpired
			case !now.Add(renewBefore).Before(pair.NotAfter):
				ds.Cert = CertExpiring
			default:
				ds.Cert = CertValid
			}
		}
		out = append(out, ds)
	}
	return out, nil
}

// StartRun launches a provisioning run in the background (the manual
// path behind POST /api/ssl/provision). The run outlives the request,
// so it does not take a context; results land in Status.
func (p *Provisioner) StartRun(domains []string) {
	p.busy.Add(1)
	go func() {
		defer p.busy.Add(-1)
		p.Run(context.Background(), domains)
	}()
}

// Busy reports whether a provisioning run is in flight or queued.
func (p *Provisioner) Busy() bool {
	return p.busy.Load() > 0
}
