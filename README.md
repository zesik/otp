# otp

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
