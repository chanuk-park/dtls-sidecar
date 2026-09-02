// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

// SPIRE-issued identity for the DTLS session, in the shape Envoy uses with SPIRE:
//
//   * the credential is an X509-SVID obtained from SPIRE (never a static file, never a PSK);
//   * the peer is verified against SPIRE's trust bundle and authorized by its SPIFFE ID;
//   * both the SVID and the bundle are STREAMED, and the current one is read at each
//     handshake, so rotation is picked up without restarting anything.
//
// Two ways to get that identity, and they make different trust assumptions:
//
//   workload API  attests the CALLER. Correct when the sidecar is what SPIRE should be
//                 issuing to; only as strong as the selectors on its entry.
//   delegated     names the NF's pid and lets SPIRE attest THAT process by its own
//                 attestors (unix path/sha256, container, k8s pod/service account). This is
//                 the Envoy-equivalent for a sidecar that cannot live inside the pod: the
//                 certificate presented on N4 is the one SPIRE issues for the NF itself.
//
// §2 D3: no PSK, no static cert, no skip-verify of the SPIFFE identity.

import (
	"context"
	"crypto/tls"
	"fmt"

	dtls "github.com/pion/dtls/v3"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// credSource is what both identity paths provide: the SVID to present now, the bundle to
// verify peers against, this side's own id, and a signal when a new SVID arrives.
type credSource interface {
	x509bundle.Source
	certificate() *tls.Certificate
	id() string
	rotations() <-chan struct{}
	close()
}

type identity struct {
	src    credSource
	cfg    *dtls.Config
	spiffe string
	mode   string // "workloadapi" | "delegated"
}

// --- workload API source (attests this process) ------------------------------------------

type workloadAPISource struct {
	src *workloadapi.X509Source
	rot chan struct{} // never signalled: X509Source refreshes in place, see note below
}

func (w *workloadAPISource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return w.src.GetX509BundleForTrustDomain(td)
}

func (w *workloadAPISource) certificate() *tls.Certificate {
	svid, err := w.src.GetX509SVID()
	if err != nil || len(svid.Certificates) == 0 {
		return nil
	}
	chain := make([][]byte, len(svid.Certificates))
	for i, c := range svid.Certificates {
		chain[i] = c.Raw
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: svid.PrivateKey, Leaf: svid.Certificates[0]}
}

func (w *workloadAPISource) id() string {
	if svid, err := w.src.GetX509SVID(); err == nil {
		return svid.ID.String()
	}
	return ""
}

// X509Source rotates internally; because certificate() re-reads it at each handshake, a
// rotated SVID is presented on the next handshake without any signal being needed here.
func (w *workloadAPISource) rotations() <-chan struct{} { return w.rot }
func (w *workloadAPISource) close()                     { w.src.Close() }

// --- delegated source (attests the NF's pid) ---------------------------------------------

func (d *delegatedSource) rotations() <-chan struct{} { return d.rotated }
func (d *delegatedSource) close()                     {}

// -----------------------------------------------------------------------------------------

// loadIdentity builds the DTLS config. workloadPID > 0 selects the delegated path, which
// needs the agent's admin (delegated identity) socket rather than the public one.
func loadIdentity(ctx context.Context, sockPath, delegatedSock string, workloadPID int,
	selfID, peerID string, server bool, mtu int) (*identity, error) {
	pid, err := spiffeid.FromString(peerID)
	if err != nil {
		return nil, fmt.Errorf("peer SPIFFE id %q: %w", peerID, err)
	}

	var src credSource
	mode := "workloadapi"
	if workloadPID > 0 {
		if delegatedSock == "" {
			return nil, fmt.Errorf("-workload-pid needs -delegated-socket (the agent's admin socket)")
		}
		ds := newDelegatedSource(delegatedSock, int32(workloadPID), selfID)
		if err := ds.run(ctx); err != nil {
			return nil, err
		}
		src, mode = ds, "delegated"
	} else {
		if sockPath == "" {
			return nil, fmt.Errorf("no SPIRE Workload API socket (set -spiffe-socket or CIRRUS_SPIRE_SOCKET)")
		}
		// A workload can legitimately match several registration entries, so the Workload
		// API hands back a SET of SVIDs and "the first one" is whatever SPIRE ordered them
		// in -- presenting it means presenting an arbitrary identity. Pick the one we were
		// told to present, exactly as the delegated path does.
		opts := []workloadapi.X509SourceOption{
			workloadapi.WithClientOptions(workloadapi.WithAddr(sockPath)),
		}
		if selfID != "" {
			opts = append(opts, workloadapi.WithDefaultX509SVIDPicker(
				func(svids []*x509svid.SVID) *x509svid.SVID {
					for _, sv := range svids {
						if sv.ID.String() == selfID {
							return sv
						}
					}
					return nil // none matched: fail closed rather than present another identity
				}))
		}
		s, err := workloadapi.NewX509Source(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("X509Source (SPIRE fetch): %w", err)
		}
		src = &workloadAPISource{src: s, rot: make(chan struct{})}
	}
	if src.certificate() == nil {
		src.close()
		if selfID != "" {
			return nil, fmt.Errorf("SPIRE issued no SVID for %s -- is there a registration "+
				"entry for that identity whose selectors match this workload?", selfID)
		}
		return nil, fmt.Errorf("SPIRE returned no usable SVID")
	}

	// Serve whatever SVID is current at handshake time instead of freezing one into the
	// config -- this is what lets a rotation take effect the way Envoy's SDS hot-swap does.
	get := func() (*tls.Certificate, error) {
		if c := src.certificate(); c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("no current SVID")
	}

	// tlsconfig has no DTLS builder, but its VerifyPeerCertificate has the identical
	// signature pion expects, so SPIFFE bundle verification + ID authorization drop in.
	// Passing src (not a snapshot) means bundle updates apply immediately.
	verify := tlsconfig.VerifyPeerCertificate(src, tlsconfig.AuthorizeID(pid))

	cfg := &dtls.Config{
		GetCertificate:       func(*dtls.ClientHelloInfo) (*tls.Certificate, error) { return get() },
		GetClientCertificate: func(*dtls.CertificateRequestInfo) (*tls.Certificate, error) { return get() },
		VerifyPeerCertificate: verify,
		// InsecureSkipVerify MUST be true for SPIFFE mutual auth. It disables only the
		// default hostname / system-root-pool check (a SPIFFE ID is not a DNS name and
		// SVIDs do not chain to public roots), which is REPLACED by the stronger
		// VerifyPeerCertificate above: full chain verification against the live SPIRE
		// bundle plus SPIFFE-ID authorization. This is what go-spiffe's own
		// tlsconfig.MTLS*Config sets (v2.5.0 config.go:25,73). Setting it false makes
		// pion verify SVIDs against the empty system pool and every handshake fails
		// "certificate signed by unknown authority" (observed).
		InsecureSkipVerify: true,
		// ECDHE-ECDSA/P-256 matches SPIRE's default ca_key_type (ec-p256); no PSK suites,
		// and nothing deliberately slow (§9.1 patch 3, D4).
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		MTU:          mtu,
	}
	if server {
		cfg.ClientAuth = dtls.RequireAnyClientCert
	}
	return &identity{src: src, cfg: cfg, spiffe: src.id(), mode: mode}, nil
}

func (i *identity) close() {
	if i != nil && i.src != nil {
		i.src.close()
	}
}
