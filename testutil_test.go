package anoncred

import (
	"crypto/ed25519"
	"encoding/hex"
)

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func edKeyForTest() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

func edSign(k ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(k, msg) }
