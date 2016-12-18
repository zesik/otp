package otp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHOTP(t *testing.T) {
	for _, algorithm := range []HashAlgorithm{HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA512} {
		generator, err := NewHOTP(algorithm, nil, 6)
		assert.NoError(t, err)
		assert.IsType(t, &hotpManager{}, generator)
		hotp := generator.(*hotpManager)
		assert.NotNil(t, hotp.secret)
		keySize, _ := algorithm.DefaultKeyByteSize()
		assert.Len(t, hotp.secret, keySize)
	}
}

func TestNewHOTPFailure(t *testing.T) {
	if _, err := NewHOTP(-1, nil, 6); assert.Error(t, err) {
		assert.Equal(t, "unknown hash algorithm", err.Error())
	}
	if _, err := NewHOTP(HashAlgorithmSHA1, nil, 0); assert.Error(t, err) {
		assert.Equal(t, "invalid code digit", err.Error())
	}
	if _, err := NewHOTP(HashAlgorithmSHA1, nil, 10); assert.Error(t, err) {
		assert.Equal(t, "invalid code digit", err.Error())
	}
}

func TestHOTPGenerateRFC(t *testing.T) {
	for _, testCase := range hotpTestMatrix {
		secret, _ := hex.DecodeString(testCase.HexSecretString)
		generator, err := NewHOTP(testCase.HashAlgorithm, secret, testCase.CodeDigits)
		assert.NoError(t, err)
		actual := generator.Generate(testCase.MovingFactor)
		assert.Equal(t, testCase.Expected, actual)
	}
}

func TestHOTPValidateRFC(t *testing.T) {
	for _, testCase := range hotpTestMatrix {
		secret, _ := hex.DecodeString(testCase.HexSecretString)
		generator, err := NewHOTP(testCase.HashAlgorithm, secret, testCase.CodeDigits)
		assert.NoError(t, err)
		match := generator.Validate(testCase.MovingFactor, testCase.Expected)
		assert.True(t, match)
	}
}

func TestNewTOTP(t *testing.T) {
	for _, algorithm := range []HashAlgorithm{HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA512} {
		generator, err := NewTOTP(algorithm, nil, 6, 30, 0, 0)
		assert.NoError(t, err)
		assert.IsType(t, &totpManager{}, generator)
	}
}

func TestNewTOTPFailure(t *testing.T) {
	if _, err := NewTOTP(-1, nil, 6, 30, 0, 0); assert.Error(t, err) {
		assert.Equal(t, "unknown hash algorithm", err.Error())
	}
	if _, err := NewTOTP(HashAlgorithmSHA1, nil, 0, 30, 0, 0); assert.Error(t, err) {
		assert.Equal(t, "invalid code digit", err.Error())
	}
	if _, err := NewTOTP(HashAlgorithmSHA1, nil, 10, 30, 0, 0); assert.Error(t, err) {
		assert.Equal(t, "invalid code digit", err.Error())
	}
	if _, err := NewTOTP(HashAlgorithmSHA1, nil, 6, 0, 0, 0); assert.Error(t, err) {
		assert.Equal(t, "invalid time step", err.Error())
	}
	if _, err := NewTOTP(HashAlgorithmSHA1, nil, 6, 30, -1, 0); assert.Error(t, err) {
		assert.Equal(t, "invalid look-backward value", err.Error())
	}
	if _, err := NewTOTP(HashAlgorithmSHA1, nil, 6, 30, 0, -1); assert.Error(t, err) {
		assert.Equal(t, "invalid look-forward value", err.Error())
	}
}

func TestTOTPGenerateRFC(t *testing.T) {
	for _, testCase := range totpTestMatrix {
		secret, _ := hex.DecodeString(testCase.HexSecretString)
		generator, err := NewTOTP(testCase.HashAlgorithm, secret, testCase.CodeDigits, testCase.TimeStep, 0, 0)
		assert.NoError(t, err)
		actual := generator.Generate(testCase.Epoch)
		assert.Equal(t, testCase.Expected, actual)
	}
}

func TestTOTPValidateRFC(t *testing.T) {
	for _, testCase := range totpTestMatrix {
		secret, _ := hex.DecodeString(testCase.HexSecretString)
		generator, err := NewTOTP(testCase.HashAlgorithm, secret, testCase.CodeDigits, testCase.TimeStep, 0, 0)
		assert.NoError(t, err)
		match := generator.Validate(testCase.Epoch, testCase.Expected)
		assert.True(t, match)
	}
}

func TestTOTPValidateBackwardForward(t *testing.T) {
	secret, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	generator, err := NewTOTP(HashAlgorithmSHA1, secret, 8, 30, 1, 2)
	assert.NoError(t, err)
	match := generator.Validate(1234567900-90, "89005924")
	assert.False(t, match)
	match = generator.Validate(1234567900-60, "89005924")
	assert.True(t, match)
	match = generator.Validate(1234567900-30, "89005924")
	assert.True(t, match)
	match = generator.Validate(1234567900, "89005924")
	assert.True(t, match)
	match = generator.Validate(1234567900+30, "89005924")
	assert.True(t, match)
	match = generator.Validate(1234567900+60, "89005924")
	assert.False(t, match)
}

type hotpTestVector struct {
	HashAlgorithm   HashAlgorithm
	HexSecretString string
	CodeDigits      int
	MovingFactor    int64
	Expected        string
}

var hotpTestMatrix = []hotpTestVector{
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 0, "755224"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 1, "287082"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 2, "359152"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 3, "969429"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 4, "338314"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 5, "254676"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 6, "287922"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 7, "162583"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 8, "399871"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 6, 9, "520489"},
}

type totpTestVector struct {
	HashAlgorithm   HashAlgorithm
	HexSecretString string
	CodeDigits      int
	TimeStep        int
	Epoch           int64
	Expected        string
}

var totpTestMatrix = []totpTestVector{
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 59, "94287082"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 59, "46119246"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 59, "90693936"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 1111111109, "07081804"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 1111111109, "68084774"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 1111111109, "25091201"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 1111111111, "14050471"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 1111111111, "67062674"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 1111111111, "99943326"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 1234567890, "89005924"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 1234567890, "91819424"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 1234567890, "93441116"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 2000000000, "69279037"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 2000000000, "90698825"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 2000000000, "38618901"},
	{HashAlgorithmSHA1, "3132333435363738393031323334353637383930", 8, 30, 20000000000, "65353130"},
	{HashAlgorithmSHA256, "3132333435363738393031323334353637383930" +
		"313233343536373839303132", 8, 30, 20000000000, "77737706"},
	{HashAlgorithmSHA512, "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"313233343536373839303132333435363738393031323334", 8, 30, 20000000000, "47863826"},
}
