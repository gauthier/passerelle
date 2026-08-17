package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gauthier/passerelle/internal/tlsutil"
)

type Quotas struct {
	MaxDevices int `json:"max_devices"`
	MaxTunnels int `json:"max_tunnels"`
	MaxConns   int `json:"max_conns"`
}

func DefaultQuotas() Quotas {
	return Quotas{MaxDevices: 5, MaxTunnels: 10, MaxConns: 100}
}

type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Quotas    Quotas    `json:"quotas"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	ClientID    string    `json:"client_id"`
	UserID      string    `json:"user_id"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	Revoked     bool      `json:"revoked"`
	CreatedAt   time.Time `json:"created_at"`
}

type tokenRecord struct {
	Hash      string    `json:"hash"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Consumed  bool      `json:"consumed"`
}

type Store struct {
	dir string
	mu  sync.Mutex
	CA  *tlsutil.CA
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca, err := tlsutil.LoadOrCreateCA(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, CA: ca}
	for _, name := range []string{"users.json", "tokens.json", "devices.json", "revoked.json"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, []byte("[]\n"), 0o600); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) AddUser(name string, q Quotas) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.readUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Name == name || u.ID == name {
			if u.Revoked {
				u.Revoked = false
				u.Quotas = q
				if err := s.writeUsers(users); err != nil {
					return nil, err
				}
				return &u, nil
			}
			return nil, fmt.Errorf("user %q already exists", name)
		}
	}
	if q.MaxDevices == 0 {
		q = DefaultQuotas()
	}
	u := User{ID: name, Name: name, Quotas: q, CreatedAt: time.Now().UTC()}
	users = append(users, u)
	if err := s.writeUsers(users); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readUsers()
}

func (s *Store) RevokeUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.readUsers()
	if err != nil {
		return err
	}
	found := false
	for i := range users {
		if users[i].Name == name || users[i].ID == name {
			users[i].Revoked = true
			found = true
		}
	}
	if !found {
		return fmt.Errorf("user %q not found", name)
	}
	devices, err := s.readDevices()
	if err != nil {
		return err
	}
	for i := range devices {
		if devices[i].UserID == name {
			devices[i].Revoked = true
		}
	}
	if err := s.writeDevices(devices); err != nil {
		return err
	}
	return s.writeUsers(users)
}

func (s *Store) User(id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.readUsers()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].ID == id || users[i].Name == id {
			u := users[i]
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user %q not found", id)
}

func (s *Store) CreateToken(userID string, ttl time.Duration) (plain string, err error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	u, err := s.User(userID)
	if err != nil {
		return "", err
	}
	if u.Revoked {
		return "", fmt.Errorf("user %q is revoked", userID)
	}
	var buf [24]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	plain = "psg_tok_" + hex.EncodeToString(buf[:])
	rec := tokenRecord{
		Hash:      hashToken(plain),
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens, err := s.readTokens()
	if err != nil {
		return "", err
	}
	tokens = append(tokens, rec)
	if err := s.writeTokens(tokens); err != nil {
		return "", err
	}
	return plain, nil
}

func (s *Store) ConsumeToken(plain string) (userID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashToken(plain)
	tokens, err := s.readTokens()
	if err != nil {
		return "", err
	}
	now := time.Now()
	for i := range tokens {
		t := &tokens[i]
		if t.Hash != h {
			continue
		}
		if t.Consumed {
			return "", fmt.Errorf("token already used")
		}
		if now.After(t.ExpiresAt) {
			return "", fmt.Errorf("token expired")
		}
		t.Consumed = true
		if err := s.writeTokens(tokens); err != nil {
			return "", err
		}
		return t.UserID, nil
	}
	return "", fmt.Errorf("invalid token")
}

func (s *Store) Enroll(userID, csrPEM string) (certPEM []byte, clientID, serial string, err error) {
	u, err := s.User(userID)
	if err != nil {
		return nil, "", "", err
	}
	if u.Revoked {
		return nil, "", "", fmt.Errorf("user %q is revoked", userID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	devices, err := s.readDevices()
	if err != nil {
		return nil, "", "", err
	}
	active := 0
	for _, d := range devices {
		if d.UserID == userID && !d.Revoked {
			active++
		}
	}
	if active >= u.Quotas.MaxDevices {
		return nil, "", "", fmt.Errorf("device quota exceeded (%d)", u.Quotas.MaxDevices)
	}
	clientID, err = randomID("dev")
	if err != nil {
		return nil, "", "", err
	}
	certPEM, serial, err = s.CA.IssueFromCSR([]byte(csrPEM), userID, clientID)
	if err != nil {
		return nil, "", "", err
	}
	devices = append(devices, Device{
		ClientID:  clientID,
		UserID:    userID,
		Serial:    serial,
		CreatedAt: time.Now().UTC(),
	})
	if err := s.writeDevices(devices); err != nil {
		return nil, "", "", err
	}
	return certPEM, clientID, serial, nil
}

func (s *Store) ListDevices(userID string) ([]Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readDevices()
	if err != nil {
		return nil, err
	}
	if userID == "" {
		return all, nil
	}
	var out []Device
	for _, d := range all {
		if d.UserID == userID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *Store) RevokeDevice(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	devices, err := s.readDevices()
	if err != nil {
		return err
	}
	found := false
	for i := range devices {
		if devices[i].ClientID == clientID {
			devices[i].Revoked = true
			found = true
		}
	}
	if !found {
		return fmt.Errorf("device %q not found", clientID)
	}
	return s.writeDevices(devices)
}

func (s *Store) CheckDevice(userID, clientID, serial string) error {
	u, err := s.User(userID)
	if err != nil {
		return err
	}
	if u.Revoked {
		return fmt.Errorf("user revoked")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	devices, err := s.readDevices()
	if err != nil {
		return err
	}
	for _, d := range devices {
		if d.ClientID == clientID {
			if d.Revoked {
				return fmt.Errorf("device revoked")
			}
			if d.UserID != userID {
				return fmt.Errorf("device user mismatch")
			}
			return nil
		}
	}
	return fmt.Errorf("unknown device")
}

func (s *Store) DeviceCount(userID string) (int, error) {
	devs, err := s.ListDevices(userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range devs {
		if !d.Revoked {
			n++
		}
	}
	return n, nil
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func randomID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

func (s *Store) readUsers() ([]User, error) {
	return readJSON[User](filepath.Join(s.dir, "users.json"))
}
func (s *Store) writeUsers(v []User) error {
	return writeJSON(filepath.Join(s.dir, "users.json"), v)
}
func (s *Store) readTokens() ([]tokenRecord, error) {
	return readJSON[tokenRecord](filepath.Join(s.dir, "tokens.json"))
}
func (s *Store) writeTokens(v []tokenRecord) error {
	return writeJSON(filepath.Join(s.dir, "tokens.json"), v)
}
func (s *Store) readDevices() ([]Device, error) {
	return readJSON[Device](filepath.Join(s.dir, "devices.json"))
}
func (s *Store) writeDevices(v []Device) error {
	return writeJSON(filepath.Join(s.dir, "devices.json"), v)
}

func readJSON[T any](path string) ([]T, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var v []T
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
