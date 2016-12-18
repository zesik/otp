// Package otp provides the HMAC-based one-time password (HOTP) algorithm described in RFC 4226 and
// the time-based one time password (TOTP) algorithm described in RFC 6238.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
)

// HashAlgorithm identifies the hash algorithm used for HMAC.
type HashAlgorithm int

const (
	// HashAlgorithmSHA1 represents SHA1 algorithm.
	HashAlgorithmSHA1 HashAlgorithm = iota

	// HashAlgorithmSHA256 represents SHA256 algorithm.
	HashAlgorithmSHA256

	// HashAlgorithmSHA512 represents SHA512 algorithm.
	HashAlgorithmSHA512
)

const (
	// maxCodeDigits represents maximum digits of password code.
	maxCodeDigits = 8
)

// hash gets the hash function specified by the algorithm enum.
func (algorithm HashAlgorithm) hash() (func() hash.Hash, error) {
	switch algorithm {
	case HashAlgorithmSHA1:
		return sha1.New, nil
	case HashAlgorithmSHA256:
		return sha256.New, nil
	case HashAlgorithmSHA512:
		return sha512.New, nil
	default:
		return nil, errors.New("unknown hash algorithm")
	}
}

// defaultKeyByteSize gets the default value of HMAC key size in bytes.
func (algorithm HashAlgorithm) defaultKeyByteSize() int {
	switch algorithm {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA512:
		return 64
	default:
		panic("unknown hash algorithm")
	}
}

// generateSecret generates a new secret key.
func (algorithm HashAlgorithm) generateSecret() ([]byte, error) {
	keyByteSize := algorithm.defaultKeyByteSize()
	secret := make([]byte, keyByteSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// OTPManager represents an HMAC-based or time-based one-time password generator and validator.
type OTPManager interface {
	// Generate generates the one-time password with the specified moving factor.
	Generate(int64) string

	// Validate validates whether the one-time password matches.
	Validate(int64, string) bool
}

// hotpManager represents an HMAC-based one-time password (HOTP) generator and validator.
type hotpManager struct {
	hashAlgorithm func() hash.Hash
	secret        []byte
	codeDigits    int
}

// NewHOTP creates a new HMAC-based one-time password (HOTP) manager with specified hash algorithm, secret keys and
// digit count of password codes.
//
// When provided secret key is nil, a new secret key will be generated with cryptographically secure pseudo-random
// number generator provided by the operation system. By default, length of the secret key is 20 bytes for SHA1
// algorithm, 32 bytes for SHA256 algorithm and 64 bytes for SHA512 algorithm.
//
// Code digit cannot be longer than 8 digits.
func NewHOTP(algorithm HashAlgorithm, secret []byte, codeDigit int) (OTPManager, error) {
	var generator hotpManager

	// Check algorithm
	hashAlgorithm, err := algorithm.hash()
	if err != nil {
		return nil, err
	}
	generator.hashAlgorithm = hashAlgorithm

	// Check secret key
	if secret == nil {
		generator.secret, err = algorithm.generateSecret()
		if err != nil {
			return nil, err
		}
	} else {
		generator.secret = secret
	}

	// Check code digits
	if codeDigit <= 0 || codeDigit > maxCodeDigits {
		return nil, errors.New("invalid code digit")
	}
	generator.codeDigits = codeDigit

	return &generator, nil
}

func (generator *hotpManager) Generate(movingFactor int64) string {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(movingFactor))

	mac := hmac.New(generator.hashAlgorithm, generator.secret)
	mac.Write(message)
	hashResult := mac.Sum(nil)

	offset := hashResult[len(hashResult)-1] & 0xf
	truncated := binary.BigEndian.Uint32(hashResult[offset:offset+4]) & 0x7fffffff
	code := truncated % uint32(math.Pow10(generator.codeDigits))

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", generator.codeDigits), code)
}

func (generator *hotpManager) Validate(movingFactor int64, code string) bool {
	return generator.Generate(movingFactor) == code
}

// totpManager represents an time-based one-time password (HOTP) generator and validator.
type totpManager struct {
	hotp         *hotpManager
	timeStep     int
	lookBackward int
	lookForward  int
}

// NewTOTP initializes a new time-based one-time password (TOTP) manager with specified hash algorithm, secret key,
// digit count of password codes, time step, and tolerant time steps.
//
// A new secret key will be generated if provided one is nil. Refers to NewHOTP function for details.
//
// Code digit cannot be longer than 8 digits.
//
// Tolerant time steps are only used for validating. These parameters can be used to allow certain clock drift
// between a client and the TOTP manager. Settings to 0 to accept no time drift at all.
func NewTOTP(algorithm HashAlgorithm, secret []byte, codeDigit, timeStep, lookBackward, lookForward int) (OTPManager, error) {
	var generator totpManager

	hotp, err := NewHOTP(algorithm, secret, codeDigit)
	if err != nil {
		return nil, err
	}
	generator.hotp = hotp.(*hotpManager)

	if timeStep <= 0 {
		return nil, errors.New("invalid time step")
	}
	generator.timeStep = timeStep

	if lookBackward < 0 {
		return nil, errors.New("invalid look-backward value")
	}
	generator.lookBackward = lookBackward

	if lookForward < 0 {
		return nil, errors.New("invalid look-forward value")
	}
	generator.lookForward = lookForward

	return &generator, nil
}

func (generator *totpManager) Generate(epoch int64) string {
	return generator.hotp.Generate(epoch / int64(generator.timeStep))
}

func (generator *totpManager) Validate(epoch int64, code string) bool {
	for i := -generator.lookBackward; i <= generator.lookForward; i += 1 {
		movingFactor := (epoch + int64(i*generator.timeStep)) / int64(generator.timeStep)
		if generator.hotp.Generate(movingFactor) == code {
			return true
		}
	}
	return false
}
