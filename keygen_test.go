package agekd

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
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
		id, err := X25519IdentityFromKey(c.key, c.salt)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		if id.String() != c.expID {
			t.Fatalf("age identity mismatch: expected '%s' got '%s'", c.expID, id.String())
		}
		if id.Recipient().String() != c.expRcp {
			t.Fatalf("age recipient mismatch: expected '%s' got '%s'", c.expRcp, id.Recipient().String())
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
			expID:  "AGE-SECRET-KEY-1UMXWX6E0QA8FMSNF3UL5X3XZYZEEF4F2LREVDXMKE5AUHC2VUFUQFNNP4W",
			expRcp: "age1hscrfgq902pphj5ud079legdfsrm0rnm0qm6aednvadsqe86nypsd8e733",
		},
		{
			key:    nil,
			salt:   nil,
			expID:  "AGE-SECRET-KEY-1UMXWX6E0QA8FMSNF3UL5X3XZYZEEF4F2LREVDXMKE5AUHC2VUFUQFNNP4W",
			expRcp: "age1hscrfgq902pphj5ud079legdfsrm0rnm0qm6aednvadsqe86nypsd8e733",
		},
		{
			key:    []byte("hello"),
			salt:   nil,
			expID:  "AGE-SECRET-KEY-14ZKXYZN0Q3GW34EFALJC9PF00VWW30YRSESQ92HSQHV6JK4S3ASQQ56X9Q",
			expRcp: "age1rp37sglsdesggn5lux9gcvc54gqw67aq87prpzjyeg2l9j0rtc0sd3k4xr",
		},
		{
			key:    []byte("hello"),
			salt:   []byte("bye"),
			expID:  "AGE-SECRET-KEY-10Z3TGEXESCSS28FUJ9SKWHXFCU99937S5PCU59HZPTH3JDZA7DNSYA02TG",
			expRcp: "age1ac25d96m7ddkldk0rnlnays373r7vk2u8jwxpgwk7c3qfjd9f93sduwhp7",
		},
		{
			key:    []byte{125, 231, 97, 121, 25, 36, 248, 109, 22, 245, 220, 7, 19, 151, 123, 246, 40, 27, 194, 4, 133, 222, 108, 216, 32, 162, 132, 16, 142, 151, 22, 104},
			salt:   []byte{62, 98, 62, 226, 73, 49, 93, 5, 172, 234, 232, 145, 139, 78, 172, 4, 139, 156, 74, 57, 215, 32, 72, 216, 17, 74, 220, 250, 146, 3, 190, 254},
			expID:  "AGE-SECRET-KEY-1DWDLKXA55WS5S4JTU9H3T3XQ5JQ55L3KQWQX6PXE9W4DRN7SZSFSCNGE7G",
			expRcp: "age1uwxxynmx5wh5weh444jyk4p7dcqyrlft08v0ltvxlnq9ds487azqdujjdr",
		},
	}
	for _, c := range testCases {
		id, err := X25519IdentityFromPassword(c.key, c.salt)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		if id.String() != c.expID {
			t.Fatalf("age identity mismatch: expected '%s' got '%s'", c.expID, id.String())
		}
		if id.Recipient().String() != c.expRcp {
			t.Fatalf("age recipient mismatch: expected '%s' got '%s'", c.expRcp, id.Recipient().String())
		}
		id2, err := X25519IdentityFromPasswordWithParameters(c.key, c.salt, DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		testIdentityEquality(t, id, id2)
	}

	id, err := X25519IdentityFromPassword([]byte("yellow"), []byte("https://"))
	if err != nil {
		t.Fatalf("failed to create age identity: %v", err)
	}
	id2, err := X25519IdentityFromPasswordWithParameters([]byte("yellow"), []byte("https://"), DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads)
	if err != nil {
		t.Fatalf("failed to create age identity: %v", err)
	}
	id3, err := newX25519IdentityFromScalar(argon2.IDKey([]byte("yellow"), []byte("https://github.com/awnumar/agekd"), DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads, curve25519.ScalarSize))
	if err != nil {
		t.Fatalf("failed to create age identity: %v", err)
	}
	testIdentityEquality(t, id, id2)
	testIdentityEquality(t, id2, id3)

	id, err = X25519IdentityFromPassword([]byte("yellow"), nil)
	if err != nil {
		t.Fatalf("failed to create age identity: %v", err)
	}
	id2, err = newX25519IdentityFromScalar(argon2.IDKey([]byte("yellow"), []byte("github.com/awnumar/agekd"), DefaultArgon2idTime, DefaultArgon2idMemory, DefaultArgon2idThreads, curve25519.ScalarSize))
	if err != nil {
		t.Fatalf("failed to create age identity: %v", err)
	}
	testIdentityEquality(t, id, id2)
}

func BenchmarkX25519IdentityFromKey(b *testing.B) {
	for range b.N {
		X25519IdentityFromKey(nil, nil)
	}
}

func BenchmarkX25519IdentityFromPassword(b *testing.B) {
	for range b.N {
		X25519IdentityFromPassword(nil, nil)
	}
}

func FuzzSaltWithLabel(f *testing.F) {
	testCases := [][]byte{
		nil,
		{},
		[]byte("hello"),
	}
	for _, testCase := range testCases {
		f.Add(testCase)
	}
	f.Fuzz(func(t *testing.T, salt []byte) {
		swl := saltWithLabel(salt)
		if !slices.Equal(swl, append(salt, []byte(kdfLabel)...)) {
			t.Fatalf("saltWithLabel has invalid value: %v", swl)
		}
	})
}

func FuzzX25519IdentityFromKey(f *testing.F) {
	testCases := []struct {
		key  []byte
		salt []byte
	}{
		{
			key:  nil,
			salt: nil,
		},
		{
			key:  []byte{},
			salt: []byte{},
		},
		{
			key:  []byte("hello"),
			salt: []byte("salt"),
		},
	}
	for _, testCase := range testCases {
		f.Add(testCase.key, testCase.salt)
	}
	f.Fuzz(func(t *testing.T, key, salt []byte) {
		id, err := X25519IdentityFromKey(key, salt)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		id2, err := X25519IdentityFromKey(key, salt)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		testIdentityEquality(t, id, id2)
	})
}

func FuzzX25519IdentityFromPasswordWithParameters(f *testing.F) {
	testCases := []struct {
		key  []byte
		salt []byte
	}{
		{
			key:  nil,
			salt: nil,
		},
		{
			key:  []byte{},
			salt: []byte{},
		},
		{
			key:  []byte("hello"),
			salt: []byte("salt"),
		},
	}
	for _, testCase := range testCases {
		f.Add(testCase.key, testCase.salt)
	}
	f.Fuzz(func(t *testing.T, password, salt []byte) {
		id, err := X25519IdentityFromPasswordWithParameters(password, salt, 1, 1, 1)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		id2, err := X25519IdentityFromPasswordWithParameters(password, salt, 1, 1, 1)
		if err != nil {
			t.Fatalf("failed to create age identity: %v", err)
		}
		testIdentityEquality(t, id, id2)
	})
}

func testIdentityEquality(t *testing.T, id, id2 *age.X25519Identity) {
	if id.String() != id2.String() {
		t.Fatalf("private identities do not match")
	}
	if id.Recipient().String() != id2.Recipient().String() {
		t.Fatalf("public recipients do not match")
	}

	out := &bytes.Buffer{}
	in, err := age.Encrypt(out, id.Recipient())
	if err != nil {
		t.Fatalf("failed to init age encryption: %v", err)
	}
	if _, err = in.Write([]byte("hello")); err != nil {
		t.Fatalf("failed to write plaintext to encrypt writer: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("failed to close encrypt writer: %v", err)
	}

	decrypted, err := age.Decrypt(out, id2)
	if err != nil {
		t.Fatalf("failed to init age decryption: %v", err)
	}
	decryptedData, err := io.ReadAll(decrypted)
	if err != nil {
		t.Fatalf("failed to read plaintext from decrypt reader: %v", err)
	}
	if string(decryptedData) != "hello" {
		t.Fatalf("plaintext mismatch! expected 'hello', got '%s'", decryptedData)
	}
}
