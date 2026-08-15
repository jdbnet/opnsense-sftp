package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"
)

type Manager struct {
	keysDir string
}

func NewManager(keysDir string) *Manager {
	return &Manager{keysDir: keysDir}
}

func (m *Manager) EnsureDir() error {
	return os.MkdirAll(m.keysDir, 0o700)
}

func (m *Manager) GenerateKeyPair() (keyID, privateKeyPath, publicKey string, err error) {
	if err := m.EnsureDir(); err != nil {
		return "", "", "", err
	}
	keyID = uuid.NewString()
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", "", fmt.Errorf("generate rsa key: %w", err)
	}
	privPEM, err := gossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return "", "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPath = filepath.Join(m.keysDir, keyID)
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(privPEM), 0o600); err != nil {
		return "", "", "", err
	}
	pub, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", "", err
	}
	publicKey = string(gossh.MarshalAuthorizedKey(pub))
	return keyID, privateKeyPath, publicKey, nil
}

func (m *Manager) LoadPrivateKey(keyID string) ([]byte, error) {
	return os.ReadFile(filepath.Join(m.keysDir, keyID))
}

func (m *Manager) HostKey() (gossh.Signer, error) {
	if err := m.EnsureDir(); err != nil {
		return nil, err
	}
	hostKeyPath := filepath.Join(m.keysDir, "host_key")
	if _, err := os.Stat(hostKeyPath); os.IsNotExist(err) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		privPEM, err := gossh.MarshalPrivateKey(privateKey, "")
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(hostKeyPath, pem.EncodeToMemory(privPEM), 0o600); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func ParseAuthorizedKey(publicKey string) (gossh.PublicKey, error) {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(publicKey))
	return pub, err
}
