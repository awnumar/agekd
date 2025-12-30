package agekd

const (
	DefaultArgon2idTime    uint32 = 4
	DefaultArgon2idMemory  uint32 = 6291456 // KiB = 6 GiB
	DefaultArgon2idThreads uint8  = 8

	kdfLabelX25519 = "github.com/awnumar/agekd"
	kdfLabelHybrid = "github.com/awnumar/agekd.hybrid"

	hybridSecretKeySize = 32
)
