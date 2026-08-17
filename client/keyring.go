package client

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const keyringService = "passerelle"
const keyringUser = "client-key"

func StorePrivateKey(pem []byte) error {
	if err := keyring.Set(keyringService, keyringUser, string(pem)); err == nil {
		_ = os.Remove(fallbackKeyPath())
		return nil
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(fallbackKeyPath(), pem, 0o600)
}

func LoadPrivateKey() ([]byte, error) {
	s, err := keyring.Get(keyringService, keyringUser)
	if err == nil && s != "" {
		return []byte(s), nil
	}
	b, err2 := os.ReadFile(fallbackKeyPath())
	if err2 != nil {
		if err != nil {
			return nil, fmt.Errorf("keyring: %w", err)
		}
		return nil, err2
	}
	return b, nil
}

func fallbackKeyPath() string {
	return filepath.Join(Dir(), "client.key")
}
