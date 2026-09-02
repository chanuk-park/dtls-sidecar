// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

// Envoy-style identity for the sidecar, via SPIRE's Delegated Identity API.
//
// Envoy gets its identity from SPIRE over SDS: it is attested as the WORKLOAD it fronts
// (it shares the pod, so the k8s attestor resolves it to that pod's namespace/service
// account), and new SVIDs are streamed to it and hot-swapped without a restart.
//
// This sidecar cannot share the NF's pod -- putting a container in it would modify the NF
// deployment, which is the whole thing we refuse to do. The ordinary Workload API attests
// its CALLER, so calling it from the host returns the sidecar's own identity, which is only
// as strong as the selectors we happen to give it ("any root process on this node" if they
// are unix:uid:0). The Delegated Identity API closes exactly that gap: an authorized
// delegate names a pid, and SPIRE performs ITS OWN attestation of the process behind it.
// So the certificate this sidecar presents on the N4 tunnel is the identity SPIRE issues
// for the NF itself -- attested from the NF's own binary/container/pod -- not one we were
// handed for being root.
//
// Both streams are long-lived, so rotation arrives the same way it does for Envoy: a new
// SVID replaces the current one and is served at the next handshake, and bundle updates
// take effect for peer verification immediately.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	delegatedv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// delegatedSource holds the identity SPIRE attests for a named pid, kept current by two
// subscriptions. It satisfies x509bundle.Source so tlsconfig's verifier can use it.
type delegatedSource struct {
	socket string
	pid    int32
	// want is the SPIFFE ID this sidecar must present. SPIRE returns every SVID the
	// delegate is entitled to see -- its own included -- so taking the first one silently
	// presents the DELEGATE's identity instead of the workload's.
	want string

	mu       sync.RWMutex
	cert     *tls.Certificate
	bundles  map[string]*x509bundle.Bundle
	spiffeID string

	haveSVID   chan struct{} // closed once the first SVID has arrived
	haveBundle chan struct{} // closed once the first bundle has arrived
	svidOnce   sync.Once
	bundleOnce sync.Once
	rotated    chan struct{} // buffered(1): a new SVID is available
}

func newDelegatedSource(socket string, pid int32, want string) *delegatedSource {
	return &delegatedSource{
		socket: socket, pid: pid, want: want,
		bundles:    map[string]*x509bundle.Bundle{},
		haveSVID:   make(chan struct{}),
		haveBundle: make(chan struct{}),
		rotated:    make(chan struct{}, 1),
	}
}

func (d *delegatedSource) dial(ctx context.Context) (*grpc.ClientConn, error) {
	target := d.socket
	if !strings.Contains(target, "://") {
		target = "unix://" + target
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// run starts both subscriptions and returns once the first SVID and bundle are in hand, so
// the caller never builds a DTLS config from an empty identity. The streams keep running.
func (d *delegatedSource) run(ctx context.Context) error {
	conn, err := d.dial(ctx)
	if err != nil {
		return fmt.Errorf("delegated: dial %s: %w", d.socket, err)
	}
	client := delegatedv1.NewDelegatedIdentityClient(conn)

	go d.watchSVIDs(ctx, client)
	go d.watchBundles(ctx, client)

	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	select {
	case <-d.haveSVID:
	case <-wait.Done():
		return fmt.Errorf("delegated: no SVID for pid %d within 20s "+
			"(is the agent's admin socket authorized for this delegate, and is there a "+
			"registration entry whose selectors match that process?)", d.pid)
	}
	select {
	case <-d.haveBundle:
	case <-wait.Done():
		return fmt.Errorf("delegated: no trust bundle within 20s")
	}
	return nil
}

func (d *delegatedSource) watchSVIDs(ctx context.Context, c delegatedv1.DelegatedIdentityClient) {
	for ctx.Err() == nil {
		stream, err := c.SubscribeToX509SVIDs(ctx,
			&delegatedv1.SubscribeToX509SVIDsRequest{Pid: d.pid})
		if err == nil {
			for {
				resp, rerr := stream.Recv()
				if rerr != nil {
					break
				}
				chosen, ids := d.pick(resp.X509Svids)
				if chosen == nil {
					logf("delegated: pid %d attested, but SPIRE returned no SVID for %s (got: %s) -- "+
						"is there a registration entry for that identity whose selectors match that process?",
						d.pid, d.want, ids)
					continue
				}
				if err := d.applySVID(chosen); err != nil {
					logf("delegated: bad SVID for pid %d: %v", d.pid, err)
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		// The stream ends when the workload does. A redeployed NF is a new pid, so this
		// sidecar's identity is no longer issuable and retrying is the honest behaviour:
		// we keep serving the last SVID until it expires, and say so.
		logf("delegated: SVID stream for pid %d ended; retrying", d.pid)
		time.Sleep(2 * time.Second)
	}
}

// pick selects the SVID whose SPIFFE ID is the one this sidecar must present, and reports
// what was on offer so a mismatch is diagnosable rather than silent.
func (d *delegatedSource) pick(list []*delegatedv1.X509SVIDWithKey) (*delegatedv1.X509SVIDWithKey, string) {
	var seen []string
	for _, sw := range list {
		if sw == nil || sw.X509Svid == nil || sw.X509Svid.Id == nil {
			continue
		}
		id := "spiffe://" + sw.X509Svid.Id.TrustDomain + sw.X509Svid.Id.Path
		seen = append(seen, id)
		if d.want == "" || id == d.want {
			return sw, strings.Join(seen, ", ")
		}
	}
	return nil, strings.Join(seen, ", ")
}

func (d *delegatedSource) applySVID(sw *delegatedv1.X509SVIDWithKey) error {
	sv := sw.X509Svid
	if sv == nil || sv.Id == nil || len(sv.CertChain) == 0 || len(sw.X509SvidKey) == 0 {
		return fmt.Errorf("incomplete SVID")
	}
	key, err := x509.ParsePKCS8PrivateKey(sw.X509SvidKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	leaf, err := x509.ParseCertificate(sv.CertChain[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	cert := &tls.Certificate{Certificate: sv.CertChain, PrivateKey: key, Leaf: leaf}
	id := "spiffe://" + sv.Id.TrustDomain + sv.Id.Path

	d.mu.Lock()
	first := d.cert == nil
	// SPIRE re-sends the whole set on every cache change, so "a message arrived" is not a
	// rotation. Compare the leaf: only a genuinely new certificate is worth re-handshaking
	// for, otherwise the session is torn down hundreds of times for nothing.
	renewed := !first && !leaf.Equal(d.cert.Leaf)
	d.cert, d.spiffeID = cert, id
	d.mu.Unlock()

	d.svidOnce.Do(func() { close(d.haveSVID) })
	if renewed {
		logf("delegated: SVID for pid %d renewed (%s, valid until %s)",
			d.pid, id, leaf.NotAfter.Format(time.RFC3339))
		select { // non-blocking: a pending rotation signal is enough
		case d.rotated <- struct{}{}:
		default:
		}
	}
	return nil
}

func (d *delegatedSource) watchBundles(ctx context.Context, c delegatedv1.DelegatedIdentityClient) {
	for ctx.Err() == nil {
		stream, err := c.SubscribeToX509Bundles(ctx, &delegatedv1.SubscribeToX509BundlesRequest{})
		if err == nil {
			for {
				resp, rerr := stream.Recv()
				if rerr != nil {
					break
				}
				d.applyBundles(resp.GetCaCertificates())
			}
		}
		if ctx.Err() != nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func (d *delegatedSource) applyBundles(cas map[string][]byte) {
	next := map[string]*x509bundle.Bundle{}
	for td, der := range cas {
		certs, err := x509.ParseCertificates(der)
		if err != nil || len(certs) == 0 {
			continue
		}
		id, err := spiffeid.TrustDomainFromString(td)
		if err != nil {
			continue
		}
		next[id.Name()] = x509bundle.FromX509Authorities(id, certs)
	}
	if len(next) == 0 {
		return
	}
	d.mu.Lock()
	d.bundles = next
	d.mu.Unlock()
	d.bundleOnce.Do(func() { close(d.haveBundle) })
}

// GetX509BundleForTrustDomain satisfies x509bundle.Source: peer verification always uses
// the bundle SPIRE last pushed, so a CA roll takes effect without restarting anything.
func (d *delegatedSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if b, ok := d.bundles[td.Name()]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("delegated: no bundle for trust domain %q", td.Name())
}

// certificate returns the SVID to present right now (read at each handshake, Envoy-style).
func (d *delegatedSource) certificate() *tls.Certificate {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cert
}

func (d *delegatedSource) id() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.spiffeID
}
