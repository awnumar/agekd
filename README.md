# Age Key Derivation - Go

[![Go Reference](https://pkg.go.dev/badge/github.com/awnumar/agekd.svg)](https://pkg.go.dev/github.com/awnumar/agekd)

`agekd` is a Go library that can be used to derive [`age`](https://github.com/FiloSottile/age) X25519 identities deterministically from keys or passwords.

This package **does not** provide a CLI. If you need that functionality, check out [age-keygen-deterministic](https://github.com/keisentraut/age-keygen-deterministic).

See the upstream `age` [documentation](https://pkg.go.dev/filippo.io/age) for further guidance on working with `age` identities and recipients.

## Installation

Inside your project folder, run:

```sh
go get github.com/awnumar/agekd
```

## Usage

To generate an age identity from a high-entropy key:

```go
identity, err := agekd.X25519IdentityFromKey(key, nil)
if err != nil {
    // handle error
}
_ = identity // *age.X25519Identity
```

To generate multiple age identities from a single key, specify a salt:

```go
identity, err := agekd.X25519IdentityFromKey(key, []byte("hello"))
```

To generate an age identity from a password:

```go
identity, err := agekd.X25519IdentityFromPassword(key, nil)
```

The default Argon2id settings are:

```go
const (
	DefaultArgon2idTime    uint32 = 8
	DefaultArgon2idMemory  uint32 = 500000 // KiB = 512 MB
	DefaultArgon2idThreads uint8  = 8
)
```

but you can provide your own with:

```go
identity, err := agekd.X25519IdentityFromPasswordWithParameters(key, nil, time, memory, threads)
```

## Licensing

Unless otherwise specified within a file, this code is distributed under the [MIT license](/LICENSE).

The [`bech32`](/bech32/) package was copied verbatim from https://github.com/FiloSottile/age/tree/v1.2.0/internal/bech32
