package agekd_test

import (
	"bytes"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/awnumar/agekd"
)

func TestX25519IdentityFromKey(t *testing.T) {
	testCases := []struct {
		key    []byte
		salt   []byte
		expID  string
		expRcp string
	}{
		{
			key:    []byte{},
			salt:   []byte{},
			expID:  "AGE-SECRET-KEY-1PM0VU8DLG8HQSYNDM9KU0E94GAQ3YZJDM0WPNSX42VYMLSNY683S0MZSU3",
			expRcp: "age1esq4c7elwuwp2xewzwyfpqcsnsrqzmn92qz5s5ttx9y4t0aymshsws8phr",
		},
		{
			key:    nil,
			salt:   nil,
			expID:  "AGE-SECRET-KEY-1PM0VU8DLG8HQSYNDM9KU0E94GAQ3YZJDM0WPNSX42VYMLSNY683S0MZSU3",
			expRcp: "age1esq4c7elwuwp2xewzwyfpqcsnsrqzmn92qz5s5ttx9y4t0aymshsws8phr",
		},
		{
			key:    []byte("hello"),
			salt:   nil,
			expID:  "AGE-SECRET-KEY-1UN5LXXQJD3HGF7MCDX8R5MH234W8TVLZQNUL38R767GX5A89DMSS0XHKKG",
			expRcp: "age18dae60ra34e6hunpfwkmpcu229ud6uv5d2jzduqygv9t760zqptslj0q97",
		},
		{
			key:    []byte("hello"),
			salt:   []byte("bye"),
			expID:  "AGE-SECRET-KEY-197FQC5NXM5SQ26WXGNCMLXVWPP4TG2AG93QG960PVEXL8P98AKWQ3DSU79",
			expRcp: "age1fx4qk3qt8su87hqt54tz8nfsywpl24cw92qklm9l6pgv0pgt3s2qmas3cg",
		},
		{
			key:    []byte{125, 231, 97, 121, 25, 36, 248, 109, 22, 245, 220, 7, 19, 151, 123, 246, 40, 27, 194, 4, 133, 222, 108, 216, 32, 162, 132, 16, 142, 151, 22, 104},
			salt:   []byte{62, 98, 62, 226, 73, 49, 93, 5, 172, 234, 232, 145, 139, 78, 172, 4, 139, 156, 74, 57, 215, 32, 72, 216, 17, 74, 220, 250, 146, 3, 190, 254},
			expID:  "AGE-SECRET-KEY-1FWLLJH77T2W0DDRNDK28X65S0LMUDJ2SLMCQHLNPH4GJ9V6A3V7SF8KFVU",
			expRcp: "age17t76vfmnhkzjlxhpt8fmdyc402sfjjr9jjq7j736nz9c6znuuu4qm5c6ds",
		},
	}
	for _, c := range testCases {
		id, err := agekd.X25519IdentityFromKey(c.key, c.salt)
		if err != nil {
			t.Errorf("failed to create age identity: %v", err)
		}
		if id.String() != c.expID {
			t.Errorf("age identity mismatch: expected '%s' got '%s'", c.expID, id.String())
		}
		if id.Recipient().String() != c.expRcp {
			t.Errorf("age recipient mismatch: expected '%s' got '%s'", c.expRcp, id.Recipient().String())
		}
	}
}

func TestX25519IdentityFromPassword(t *testing.T) {
	testCases := []struct {
		key    []byte
		salt   []byte
		expID  string
		expRcp string
	}{
		{
			key:    []byte{},
			salt:   []byte{},
			expID:  "AGE-SECRET-KEY-18HT30KVMYGPH8GJP60ZDLQ3LL35GFVQWWX6H9EH94RF6X76WKVKSL4S5JT",
			expRcp: "age13rcc6h7gcsa2zm9tusykare69dwev56mg7rq7jydm8z4w7ukz4kqpsljv3",
		},
		{
			key:    nil,
			salt:   nil,
			expID:  "AGE-SECRET-KEY-18HT30KVMYGPH8GJP60ZDLQ3LL35GFVQWWX6H9EH94RF6X76WKVKSL4S5JT",
			expRcp: "age13rcc6h7gcsa2zm9tusykare69dwev56mg7rq7jydm8z4w7ukz4kqpsljv3",
		},
		{
			key:    []byte("hello"),
			salt:   nil,
			expID:  "AGE-SECRET-KEY-1JF7DW7UFEC3C5ZYKE5LDVJ8EFXV28SY8VSYC4DLMM5DLGP92AC2QQ8U8LA",
			expRcp: "age1qzxekva6d6pd27kqmj82czqnd3c9xvden5qcw00yxmym80e7w4sqsd6qrm",
		},
		{
			key:    []byte("hello"),
			salt:   []byte("bye"),
			expID:  "AGE-SECRET-KEY-1QU2CKZHW37V0NFRCGWRVSJT7ERC96UQC6FKNZ9DD8T6V2JGTMZCQNRDD62",
			expRcp: "age1cpt3dfuuvpr73kue65h2dg0q45d02u5g8dvdpvcktgt7pjyt7slspww6kh",
		},
		{
			key:    []byte{125, 231, 97, 121, 25, 36, 248, 109, 22, 245, 220, 7, 19, 151, 123, 246, 40, 27, 194, 4, 133, 222, 108, 216, 32, 162, 132, 16, 142, 151, 22, 104},
			salt:   []byte{62, 98, 62, 226, 73, 49, 93, 5, 172, 234, 232, 145, 139, 78, 172, 4, 139, 156, 74, 57, 215, 32, 72, 216, 17, 74, 220, 250, 146, 3, 190, 254},
			expID:  "AGE-SECRET-KEY-1738FDEZTQC89XZC9TY55403TMD2LUFNAM97E4E27H55YJEH7Q6AQRPPJ3E",
			expRcp: "age1m755tmmgjk2qdetfhnkcj8cl88v7v2dv24c0xw2q08dmn7u05qdq2hud6f",
		},
	}
	for _, c := range testCases {
		id, err := agekd.X25519IdentityFromPassword(c.key, c.salt)
		if err != nil {
			t.Errorf("failed to create age identity: %v", err)
		}
		if id.String() != c.expID {
			t.Errorf("age identity mismatch: expected '%s' got '%s'", c.expID, id.String())
		}
		if id.Recipient().String() != c.expRcp {
			t.Errorf("age recipient mismatch: expected '%s' got '%s'", c.expRcp, id.Recipient().String())
		}
		id, err = agekd.X25519IdentityFromPasswordWithParameters(c.key, c.salt, agekd.DefaultArgon2idTime, agekd.DefaultArgon2idMemory, agekd.DefaultArgon2idThreads)
		if err != nil {
			t.Errorf("failed to create age identity: %v", err)
		}
		if id.String() != c.expID {
			t.Errorf("age identity mismatch: expected '%s' got '%s'", c.expID, id.String())
		}
		if id.Recipient().String() != c.expRcp {
			t.Errorf("age recipient mismatch: expected '%s' got '%s'", c.expRcp, id.Recipient().String())
		}
	}
}

func BenchmarkX25519IdentityFromKey(b *testing.B) {
	for range b.N {
		agekd.X25519IdentityFromKey(nil, nil)
	}
}

func BenchmarkX25519IdentityFromPassword(b *testing.B) {
	for range b.N {
		agekd.X25519IdentityFromPassword(nil, nil)
	}
}

func FuzzX25519IdentityFromKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, key, salt []byte) {
		id, err := agekd.X25519IdentityFromKey(key, salt)
		if err != nil {
			t.Errorf("failed to create age identity: %v", err)
		}
		id2, err := agekd.X25519IdentityFromKey(key, salt)
		if err != nil {
			t.Errorf("failed to create age identity: %v", err)
		}
		if id.String() != id2.String() {
			t.Errorf("private identities do not match")
		}
		if id.Recipient().String() != id2.Recipient().String() {
			t.Errorf("public recipients do not match")
		}

		out := &bytes.Buffer{}
		in, err := age.Encrypt(out, id.Recipient())
		if err != nil {
			t.Errorf("failed to init age encryption: %v", err)
		}
		if _, err = in.Write([]byte("hello")); err != nil {
			t.Errorf("failed to write plaintext to encrypt writer: %v", err)
		}
		if err := in.Close(); err != nil {
			t.Errorf("failed to close encrypt writer: %v", err)
		}

		decrypted, err := age.Decrypt(out, id2)
		if err != nil {
			t.Errorf("failed to init age decryption: %v", err)
		}
		decryptedData, err := io.ReadAll(decrypted)
		if err != nil {
			t.Errorf("failed to read plaintext from decrypt reader: %v", err)
		}
		if string(decryptedData) != "hello" {
			t.Errorf("plaintext mismatch! expected 'hello', got '%s'", decryptedData)
		}
	})
}
