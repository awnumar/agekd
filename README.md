# Age (Deterministic) Key Derivation

[![Go Reference](https://pkg.go.dev/badge/github.com/awnumar/agekd.svg)](https://pkg.go.dev/github.com/awnumar/agekd) [![Go workflow](https://github.com/awnumar/agekd/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/awnumar/agekd/actions/workflows/go.yml)

AgeKD is a Go library that can be used to derive [`age`](https://github.com/FiloSottile/age) X25519 identities deterministically from keys or passwords.

This package **does not** provide a CLI. If you need that functionality, check out [age-keygen-deterministic](https://github.com/keisentraut/age-keygen-deterministic).

See the upstream `age` [documentation](https://pkg.go.dev/filippo.io/age) for further guidance on working with `age` identities and recipients.

### **This package is currently pre-v1 and is therefore subject to breaking changes.**

## When would you use this?

- You already have key material and want to use it for age operations.
- Your execution environment has the capability to generate cryptographically secure keys, but it prevents your program from persisting custom keys (such as a Kubernetes pod using Hashicorp Vault).
- You want to programmatically derive age identities from passwords.

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

The default Argon2id parameters are:

```go
DefaultArgon2idTime    uint32 = 4
DefaultArgon2idMemory  uint32 = 6291456 // KiB = 6 GiB
DefaultArgon2idThreads uint8  = 8
```

which takes ~3s per hash on an AMD 5800X3D 8-Core CPU. You can select your own parameters with:

```go
identity, err := agekd.X25519IdentityFromPasswordWithParameters(key, nil, time, memory, threads)
```

For guidance on Argon2id parameter selection, refer to [rfc9106](https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice).

## Licensing

Unless otherwise specified within a file, this code is distributed under the [MIT license](/LICENSE).

The [`bech32`](/bech32/) package was copied verbatim from https://github.com/FiloSottile/age/tree/v1.2.0/internal/bech32
