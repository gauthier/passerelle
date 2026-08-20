package router

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Allocation struct {
	Hostname   string    `json:"hostname"`
	TunnelID   string    `json:"tunnel_id"`
	UserID     string    `json:"user_id"`
	ClientID   string    `json:"client_id"`
	Persist    bool      `json:"persist"`
	CreatedAt  time.Time `json:"created_at"`
	GraceUntil time.Time `json:"grace_until,omitempty"`
}

type Session interface {
	UserID() string
	ClientID() string
	OpenDataStream() (io.ReadWriteCloser, error)
}

type Registry struct {
	mu         sync.RWMutex
	byHost     map[string]*live
	byTunnel   map[string]*live
	grace      time.Duration
	baseDomain string
	onChange   func(n int)
}

type live struct {
	Allocation
	sess Session
}

func New(baseDomain string, grace time.Duration) *Registry {
	if grace <= 0 {
		grace = 2 * time.Minute
	}
	return &Registry{
		byHost:     make(map[string]*live),
		byTunnel:   make(map[string]*live),
		grace:      grace,
		baseDomain: strings.TrimPrefix(strings.ToLower(baseDomain), "."),
	}
}

func (r *Registry) BaseDomain() string { return r.baseDomain }

func (r *Registry) SetOnChange(fn func(n int)) { r.onChange = fn }

func (r *Registry) Allocate(sess Session, subdomain string, persist bool) (*Allocation, error) {
	r.mu.Lock()
	r.gcLocked(time.Now())
	host, err := r.pickHostLocked(sess.UserID(), subdomain)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	id, err := randomHex(8)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	a := &live{
		Allocation: Allocation{
			Hostname:  host,
			TunnelID:  id,
			UserID:    sess.UserID(),
			ClientID:  sess.ClientID(),
			Persist:   persist,
			CreatedAt: time.Now().UTC(),
		},
		sess: sess,
	}
	r.byHost[host] = a
	r.byTunnel[id] = a
	n := len(r.byTunnel)
	out := a.Allocation
	r.mu.Unlock()
	r.notify(n)
	return &out, nil
}

func (r *Registry) Release(tunnelID string) {
	r.mu.Lock()
	a, ok := r.byTunnel[tunnelID]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.byTunnel, tunnelID)
	delete(r.byHost, a.Hostname)
	n := len(r.byTunnel)
	r.mu.Unlock()
	r.notify(n)
}

func (r *Registry) DisconnectSession(sess Session) {
	if sess == nil {
		return
	}
	r.mu.Lock()
	now := time.Now()
	for _, a := range r.byTunnel {
		if a.sess != sess {
			continue
		}
		a.sess = nil
		if a.Persist {
			a.GraceUntil = time.Time{}
			continue
		}
		a.GraceUntil = now.Add(r.grace)
	}
	n := len(r.byTunnel)
	r.mu.Unlock()
	r.notify(n)
}

func (r *Registry) Lookup(host string) (*Allocation, Session, bool) {
	host = normalizeHost(host)
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byHost[host]
	if !ok || a.sess == nil {
		return nil, nil, false
	}
	all := a.Allocation
	return &all, a.sess, true
}

func (r *Registry) GetTunnel(id string) (*Allocation, Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byTunnel[id]
	if !ok {
		return nil, nil, false
	}
	all := a.Allocation
	return &all, a.sess, true
}

func (r *Registry) List() []Allocation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Allocation, 0, len(r.byTunnel))
	for _, a := range r.byTunnel {
		out = append(out, a.Allocation)
	}
	return out
}

func (r *Registry) CountForUser(userID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, a := range r.byTunnel {
		if a.UserID == userID && a.sess != nil {
			n++
		}
	}
	return n
}

func (r *Registry) Rebind(tunnelID string, sess Session) bool {
	r.mu.Lock()
	a, ok := r.byTunnel[tunnelID]
	if !ok || a.UserID != sess.UserID() {
		r.mu.Unlock()
		return false
	}
	a.sess = sess
	a.ClientID = sess.ClientID()
	a.GraceUntil = time.Time{}
	n := len(r.byTunnel)
	r.mu.Unlock()
	r.notify(n)
	return true
}

func (r *Registry) pickHostLocked(userID, subdomain string) (string, error) {
	if subdomain == "" {
		for i := 0; i < 16; i++ {
			id, err := randomHex(6)
			if err != nil {
				return "", err
			}
			h := id + "." + r.baseDomain
			if _, taken := r.byHost[h]; !taken {
				return h, nil
			}
		}
		return "", fmt.Errorf("could not allocate hostname")
	}
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	if err := validateSubdomain(subdomain); err != nil {
		return "", err
	}
	h := subdomain + "." + r.baseDomain
	if existing, ok := r.byHost[h]; ok {
		if existing.UserID != userID {
			return "", fmt.Errorf("subdomain %q is taken", subdomain)
		}
		if existing.sess != nil {
			return "", fmt.Errorf("subdomain %q is already in use", subdomain)
		}
		delete(r.byHost, h)
		delete(r.byTunnel, existing.TunnelID)
	}
	return h, nil
}

func (r *Registry) gcLocked(now time.Time) {
	for id, a := range r.byTunnel {
		if a.sess != nil || a.Persist {
			continue
		}
		if a.GraceUntil.IsZero() || now.After(a.GraceUntil) {
			delete(r.byTunnel, id)
			delete(r.byHost, a.Hostname)
		}
	}
}

func (r *Registry) notify(n int) {
	if r.onChange != nil {
		r.onChange(n)
	}
}

func validateSubdomain(s string) error {
	if len(s) < 1 || len(s) > 63 {
		return fmt.Errorf("invalid subdomain")
	}
	switch s {
	case "www", "gateway", "passerelle", "api", "enroll", "mail", "smtp", "wildcard":
		return fmt.Errorf("reserved subdomain")
	}
	for i, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(s)-1)
		if !ok {
			return fmt.Errorf("invalid subdomain")
		}
	}
	return nil
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func PublicURL(scheme, hostname string, port int) string {
	if port == 443 && scheme == "https" || port == 80 && scheme == "http" || port <= 0 {
		return scheme + "://" + hostname
	}
	return fmt.Sprintf("%s://%s:%d", scheme, hostname, port)
}
