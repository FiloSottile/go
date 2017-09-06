package tls

import (
	"log"
	"net"
	"syscall"
	"unsafe"
)

// https://github.com/torvalds/linux/blob/v4.13/Documentation/networking/tls.txt

const (
	TCP_ULP = 31
	SOL_TLS = 282
	TLS_TX  = 1

	kTLS_CIPHER_AES_GCM_128              = 51
	kTLS_CIPHER_AES_GCM_128_IV_SIZE      = 8
	kTLS_CIPHER_AES_GCM_128_KEY_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_SALT_SIZE    = 4
	kTLS_CIPHER_AES_GCM_128_TAG_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE = 8

	kTLSOverhead = 16
)

/* From linux/tls.h
struct tls_crypto_info {
	unsigned short version;
	unsigned short cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
}; */

type kTLSCryptoInfo struct {
	version    uint16
	cipherType uint16
	iv         [kTLS_CIPHER_AES_GCM_128_IV_SIZE]byte
	key        [kTLS_CIPHER_AES_GCM_128_KEY_SIZE]byte
	salt       [kTLS_CIPHER_AES_GCM_128_SALT_SIZE]byte
	recSeq     [kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE]byte
}

const kTLSCryptoInfoSize = 2 + 2 + kTLS_CIPHER_AES_GCM_128_IV_SIZE + kTLS_CIPHER_AES_GCM_128_KEY_SIZE +
	kTLS_CIPHER_AES_GCM_128_SALT_SIZE + kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE

// kTLSCipher is a placeholder to tell the record layer to skip wrapping.
type kTLSCipher struct{}

func kTLSEnable(c *net.TCPConn, key, iv, seq []byte) error {
	if len(key) != kTLS_CIPHER_AES_GCM_128_KEY_SIZE {
		panic("kTLS: wrong key length")
	}
	if len(iv) != kTLS_CIPHER_AES_GCM_128_SALT_SIZE {
		panic("kTLS: wrong iv length")
	}
	if len(seq) != kTLS_CIPHER_AES_GCM_128_IV_SIZE {
		panic("kTLS: wrong seq length")
	}

	cryptoInfo := kTLSCryptoInfo{
		version:    VersionTLS12,
		cipherType: kTLS_CIPHER_AES_GCM_128,
	}
	copy(cryptoInfo.salt[:], iv)
	copy(cryptoInfo.key[:], key)
	copy(cryptoInfo.iv[:], seq)
	copy(cryptoInfo.recSeq[:], seq)

	// Assert padding isn't introduced by alignment requirements.
	if unsafe.Sizeof(cryptoInfo) != kTLSCryptoInfoSize {
		panic("kTLS: wrong cryptoInfo size")
	}

	rwc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return rwc.Control(func(fd uintptr) {
		err := syscall.SetsockoptString(int(fd), syscall.SOL_TCP, TCP_ULP, "tls")
		if err != nil {
			log.Println("kTLS: setsockopt(SOL_TCP, TCP_ULP) failed:", err)
		}
		err = syscall.SetsockoptString(int(fd), SOL_TLS, TLS_TX,
			string((*[kTLSCryptoInfoSize]byte)(unsafe.Pointer(&cryptoInfo))[:]))
		if err != nil {
			log.Println("kTLS: setsockopt(SOL_TLS, TLS_TX) failed:", err)
		}
	})
}
