package auth

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(kp.PrivateKey))
	}

	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(kp.PublicKey))
	}
}

func TestKeypairFingerprint(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	fingerprint := kp.Fingerprint()

	// SHA256 produces 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("expected fingerprint length 64, got %d", len(fingerprint))
	}

	// Fingerprint should be consistent
	if kp.Fingerprint() != fingerprint {
		t.Error("fingerprint should be consistent")
	}
}

func TestSaveAndLoadKeypair(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate and save
	kp1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if err := kp1.SaveToDirectory(tmpDir); err != nil {
		t.Fatalf("SaveToDirectory failed: %v", err)
	}

	// Check files exist with correct permissions
	privPath := filepath.Join(tmpDir, "private.pem")
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("private key file not found: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected private key permissions 0600, got %o", info.Mode().Perm())
	}

	// Load and compare
	kp2, err := LoadFromDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadFromDirectory failed: %v", err)
	}

	if kp1.Fingerprint() != kp2.Fingerprint() {
		t.Error("loaded keypair fingerprint doesn't match")
	}

	// Verify keys are functionally equivalent by signing
	msg := []byte("test message")
	sig := ed25519.Sign(kp1.PrivateKey, msg)
	if !ed25519.Verify(kp2.PublicKey, msg, sig) {
		t.Error("loaded public key cannot verify signature from original private key")
	}
}

func TestLoadOrCreate(t *testing.T) {
	tmpDir := t.TempDir()

	// First call should create
	kp1, err := LoadOrCreate(tmpDir)
	if err != nil {
		t.Fatalf("LoadOrCreate (create) failed: %v", err)
	}

	// Second call should load existing
	kp2, err := LoadOrCreate(tmpDir)
	if err != nil {
		t.Fatalf("LoadOrCreate (load) failed: %v", err)
	}

	if kp1.Fingerprint() != kp2.Fingerprint() {
		t.Error("LoadOrCreate should return same keypair")
	}
}

func TestSignJWT(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	token, err := kp.SignJWT()
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	// JWT should have 3 parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	// Verify the token
	payload, err := VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if payload.Fingerprint != kp.Fingerprint() {
		t.Error("JWT fingerprint doesn't match keypair fingerprint")
	}

	if payload.Issuer != JWTIssuer {
		t.Errorf("expected issuer %s, got %s", JWTIssuer, payload.Issuer)
	}

	// Check that token expires in ~5 minutes
	expectedExpiry := time.Now().Add(TokenExpiry).Unix()
	delta := payload.ExpiresAt - expectedExpiry
	if delta < -2 || delta > 2 {
		t.Errorf("unexpected expiry: expected ~%d, got %d", expectedExpiry, payload.ExpiresAt)
	}
}

func TestVerifyJWT_InvalidSignature(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	token, err := kp.SignJWT()
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	// Tamper with the token
	parts := strings.Split(token, ".")
	parts[2] = "tamperedsignature123"
	tamperedToken := strings.Join(parts, ".")

	_, err = VerifyJWT(tamperedToken)
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestVerifyJWT_InvalidFormat(t *testing.T) {
	_, err := VerifyJWT("invalid.token")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestConfigDir(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir returned empty string")
	}

	if !strings.Contains(dir, "ovrse") {
		t.Errorf("ConfigDir should contain 'ovrse': %s", dir)
	}
}

func TestCredentialsDir(t *testing.T) {
	dir := CredentialsDir()
	if dir == "" {
		t.Error("CredentialsDir returned empty string")
	}

	if !strings.Contains(dir, "credentials") {
		t.Errorf("CredentialsDir should contain 'credentials': %s", dir)
	}
}

func TestDataDir(t *testing.T) {
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir returned empty string")
	}

	if !strings.Contains(dir, "ovrse") {
		t.Errorf("DataDir should contain 'ovrse': %s", dir)
	}
}

func TestDatabasePath(t *testing.T) {
	path := DatabasePath()
	if path == "" {
		t.Error("DatabasePath returned empty string")
	}

	if !strings.HasSuffix(path, "overseer.db") {
		t.Errorf("DatabasePath should end with 'overseer.db': %s", path)
	}
}

func TestPublicKeyBytes(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	pubBytes := kp.PublicKeyBytes()
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
}
