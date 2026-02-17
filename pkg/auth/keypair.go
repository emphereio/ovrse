// Package auth provides Ed25519 credential management and JWT signing.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Keypair holds an Ed25519 key pair for authentication.
type Keypair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateKeypair creates a new Ed25519 key pair.
func GenerateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return &Keypair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// Fingerprint returns the SHA256 fingerprint of the public key (hex encoded).
func (k *Keypair) Fingerprint() string {
	hash := sha256.Sum256(k.PublicKey)
	return hex.EncodeToString(hash[:])
}

// SaveToDirectory saves the keypair to PEM files in the specified directory.
func (k *Keypair) SaveToDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save private key
	privPath := filepath.Join(dir, "private.pem")
	if err := k.savePrivateKey(privPath); err != nil {
		return err
	}

	// Save public key
	pubPath := filepath.Join(dir, "public.pem")
	if err := k.savePublicKey(pubPath); err != nil {
		return err
	}

	return nil
}

func (k *Keypair) savePrivateKey(path string) error {
	// PKCS8 encode the private key
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

func (k *Keypair) savePublicKey(path string) error {
	// PKIX encode the public key
	pkix, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	return nil
}

// LoadFromDirectory loads a keypair from PEM files in the specified directory.
func LoadFromDirectory(dir string) (*Keypair, error) {
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	// Load private key
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	edPriv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	// Load public key
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ = pem.Decode(pubPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return &Keypair{
		PrivateKey: edPriv,
		PublicKey:  edPub,
	}, nil
}

// LoadOrCreate loads an existing keypair or creates a new one if none exists.
func LoadOrCreate(dir string) (*Keypair, error) {
	privPath := filepath.Join(dir, "private.pem")

	// Check if keypair already exists
	if _, err := os.Stat(privPath); err == nil {
		return LoadFromDirectory(dir)
	}

	// Generate new keypair
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	// Save to directory
	if err := kp.SaveToDirectory(dir); err != nil {
		return nil, err
	}

	return kp, nil
}

// PublicKeyBytes returns the raw 32-byte public key.
func (k *Keypair) PublicKeyBytes() []byte {
	return k.PublicKey
}
