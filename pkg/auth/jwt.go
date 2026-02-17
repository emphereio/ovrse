package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTHeader represents the JWT header with embedded JWK.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK *JWK   `json:"jwk"`
}

// JWK represents a JSON Web Key for Ed25519 public key.
type JWK struct {
	Kty string `json:"kty"` // Key Type: "OKP"
	Crv string `json:"crv"` // Curve: "Ed25519"
	X   string `json:"x"`   // Base64url-encoded public key
}

// JWTPayload represents the JWT claims.
type JWTPayload struct {
	Fingerprint string `json:"fingerprint"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Issuer      string `json:"iss"`
}

const (
	// TokenExpiry is how long JWT tokens are valid.
	TokenExpiry = 5 * time.Minute

	// JWTIssuer identifies tokens from ovrse-cli.
	JWTIssuer = "ovrse-cli"
)

// SignJWT creates a signed JWT token using the keypair.
func (k *Keypair) SignJWT() (string, error) {
	now := time.Now()

	// Create header with embedded public key
	header := JWTHeader{
		Alg: "EdDSA",
		Typ: "JWT",
		JWK: &JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64URLEncode(k.PublicKey),
		},
	}

	// Create payload
	payload := JWTPayload{
		Fingerprint: k.Fingerprint(),
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(TokenExpiry).Unix(),
		Issuer:      JWTIssuer,
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payloadJSON)

	// Create signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign with Ed25519
	signature := ed25519.Sign(k.PrivateKey, []byte(signingInput))
	signatureB64 := base64URLEncode(signature)

	return signingInput + "." + signatureB64, nil
}

// VerifyJWT verifies a JWT token and returns the payload.
// This is primarily for testing; the backend does the real verification.
func VerifyJWT(token string) (*JWTPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// Decode header to get public key
	headerJSON, err := base64URLDecode(headerB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	if header.JWK == nil || header.JWK.Kty != "OKP" || header.JWK.Crv != "Ed25519" {
		return nil, fmt.Errorf("invalid JWK")
	}

	// Extract public key from JWK
	pubKeyBytes, err := base64URLDecode(header.JWK.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Verify signature
	signature, err := base64URLDecode(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	signingInput := headerB64 + "." + payloadB64
	if !ed25519.Verify(pubKey, []byte(signingInput), signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode and validate payload
	payloadJSON, err := base64URLDecode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Check expiration
	now := time.Now().Unix()
	if payload.ExpiresAt < now {
		return nil, fmt.Errorf("token expired")
	}

	return &payload, nil
}

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded
}

// base64URLDecode decodes base64url string without padding.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
