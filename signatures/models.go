package signatures

import (
	"encoding/base64"
)

type Signature []byte

// StdEncoding encoding with padding (= or ==)
func (sig Signature) StdEncoding() string {
	return base64.StdEncoding.EncodeToString(sig)
}

// RawStdEncoding encoding without padding
func (sig Signature) RawStdEncoding() string {
	return base64.RawStdEncoding.EncodeToString(sig)
}

// URLEncoding encoding with padding (= or ==) and url safe characters
func (sig Signature) URLEncoding() string {
	return base64.URLEncoding.EncodeToString(sig)
}

// RawURLEncoding encoding without padding and url safe characters
func (sig Signature) RawURLEncoding() string {
	return base64.RawURLEncoding.EncodeToString(sig)
}
