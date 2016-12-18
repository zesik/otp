# otp

[![GoDoc](https://godoc.org/github.com/zesik/otp?status.svg)](https://godoc.org/github.com/zesik/otp)
[![Build Status](https://travis-ci.org/zesik/otp.svg?branch=master)](https://travis-ci.org/zesik/otp)
[![Coverage Status](https://coveralls.io/repos/github/zesik/otp/badge.svg?branch=master)](https://coveralls.io/github/zesik/otp?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/zesik/otp)](https://goreportcard.com/report/github.com/zesik/otp)

Package `otp` is an implementation of HMAC-based one-time password algorithm (RFC 4226) and
time-based one-time password algorithm (RFC 6238).

## Install

```
go get github.com/zesik/otp
```

## Quick Example

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/zesik/otp"
)

func main() {
	secret, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	otp, _ := otp.NewTOTP(otp.HashAlgorithmSHA1, secret, 8, 30, 0, 0)
	fmt.Println(otp.Generate(1234567890))             // Should print "89005924"
	fmt.Println(otp.Validate(1234567890, "89005924")) // Should print "true"
}
```

## License

[MIT](LICENSE)
