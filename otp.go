// Package otp is an easy-to-use implementation of RFC 4226 (HOTP) and RFC 6238
// (TOTP).
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"hash"
	"log"
	"strconv"
	"time"
)

type HashFunction string

const (
	SHA1   HashFunction = "SHA1"
	SHA256 HashFunction = "SHA256"
	SHA512 HashFunction = "SHA512"

	MinKeySize = 16
	MaxDigits  = 10
)

var hfMap map[HashFunction]func() hash.Hash

func init() {
	hfMap = make(map[HashFunction]func() hash.Hash)
	hfMap[SHA1] = sha1.New
	hfMap[SHA256] = sha256.New
	hfMap[SHA512] = sha512.New
}

// Represents an HOTP parameter-set. SecretKey must be base-32 encoded.
type HOTPKey struct {
	SecretKey    string       `json:"secret_key"` // Base-32
	HashFunction HashFunction `json:"hash_function"`
	Digits       byte         `json:"digits"`
	Counter      uint64       `json:"counter"`
}

// Computes and returns the OTP using HOTP parameters. If the underlying HOTPKey
// is invalid, the program exits using log.Fatal.
func (k *HOTPKey) OTP() string {
	if !k.Validate() {
		log.Fatalln("invalid key parameters")
	}
	ctri := k.Counter
	var ctr [8]byte
	for i := len(ctr) - 1; i >= 0; i-- {
		ctr[i] = byte(ctri & 0xFF)
		ctri >>= 8
	}
	sk, _ := base32.StdEncoding.DecodeString(k.SecretKey)
	mac := hmac.New(hfMap[k.HashFunction], sk)
	mac.Write(ctr[:])
	mres := mac.Sum(nil)
	i := mres[len(mres)-1] & 0x0F
	b := int(mres[i])<<24 | int(mres[i+1])<<16 |
		int(mres[i+2])<<8 | int(mres[i+3])
	b &= 0x7FFFFFFF
	res := ""
	for i := 0; i < int(k.Digits); i++ {
		res = strconv.FormatInt(int64(b%10), 10) + res
		b /= 10
	}
	return res
}

// Validates an HOTPKey.
func (k *HOTPKey) Validate() bool {
	sk, err := base32.StdEncoding.DecodeString(k.SecretKey)
	return len(sk) >= MinKeySize && hfMap[k.HashFunction] != nil &&
		k.Digits <= MaxDigits && k.Digits > 0 && err == nil
}

// Represents a TOTP parameter-set. Like in HOTPKey, SecretKey must be base-32
// encoded. Even though T0 not a parameter in virtually all other
// implementations, according to RFC 6238, it is not necessarily always 0. Go's
// zero-value mechanism works well here.
type TOTPKey struct {
	SecretKey    string       `json:"secret_key"`
	HashFunction HashFunction `json:"hash_function"`
	Digits       byte         `json:"digits"`
	TimeStep     uint64       `json:"time_step"`
	T0           uint64       `json:"t0"`
}

// Computes and returns the OTP using TOTP parameters. If the underlying TOTPKey
// is invalid, the program exits using log.Fatal.
func (k *TOTPKey) OTP() string {
	h := k.conv()
	if !h.Validate() {
		log.Fatalln("invalid key parameters")
	}
	return h.OTP()
}

// Converts a TOTPKey into an HOTPKey.
func (k *TOTPKey) conv() *HOTPKey {
	steps := (uint64(time.Now().Unix()) - k.T0) / k.TimeStep
	return &HOTPKey{
		k.SecretKey,
		k.HashFunction,
		k.Digits,
		steps,
	}
}

// Validates a TOTPKey.
func (k *TOTPKey) Validate() bool {
	return k.T0 >= 0 && k.TimeStep > 0 && k.conv().Validate()
}
