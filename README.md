# otp

[![Go Reference](https://pkg.go.dev/badge/codeberg.org/ar324/otp.svg)](https://pkg.go.dev/codeberg.org/ar324/otp)

`otp` is an easy-to-use implementation of RFC 4226 (HOTP) and RFC 6238 (TOTP) in
Go.

Only base-32 encoded secret-keys are supported.

Supported hash functions: `SHA1`, `SHA256`, and `SHA512` (the latter two from
the SHA-2 family, not SHA-3).

## Usage Overview

```go
package main

import (
	"fmt"
	"log"

	"codeberg.org/ar324/otp"
)

func main() {
	// HOTP
	hk := otp.HOTPKey{
		SecretKey:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		HashFunction: otp.SHA1,
		Digits:       8,
		Counter:      0x0000000000000001,
	}
	if !hk.Validate() {
		log.Fatalln("invalid HOTP parameters")
	}
	fmt.Println(hk.OTP()) // prints "94287082"

	// TOTP
	tk := otp.TOTPKey{
		SecretKey:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		HashFunction: otp.SHA512,
		Digits:       8,
		TimeStep:     60,
	}
	if !tk.Validate() {
		log.Fatalln("invalid TOTP parameters")
	}
	tk.OTP() // "88486101"
}
```
