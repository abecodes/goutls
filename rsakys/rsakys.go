package rsakys

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

type pemFormat uint

const (
	privateType         = "RSA PRIVATE KEY"
	publicType          = "RSA PUBLIC KEY"
	privateSuffix       = "pem"
	publicSuffix        = "pub"
	tenKB         int64 = 10 * 1024
)

const (
	pkcs1 pemFormat = iota
	pkcs8
	pkix
)

var (
	errWrongPrivateType = errors.New("key is not of type RSA PRIVATE KEY")
	errWrongPublicType  = errors.New("key is not of type RSA PUBLIC KEY")
	errParse            = errors.New("unable to parse the given key")
)

// ReadPrivate reads a private key PEM file and returns the private key struct
func ReadPrivate(path string) (*rsa.PrivateKey, error) {
	return readPrivate(path)
}

// ReadPublic reads a public key PEM file and returns the public key struct
func ReadPublic(path string) (*rsa.PublicKey, error) {
	return readPublic(path)
}

// ReadPrivatePKCS1 reads a private key PEM file and returns a PKCS1 encoded private key byte slice
func ReadPrivatePKCS1(path string) ([]byte, error) {
	key, err := readPrivate(path)
	if err != nil {
		return nil, err
	}

	return encodePrivateKey(key, pkcs1)
}

// ReadPrivatePKCS8  reads a private key PEM file and returns a PKCS8 encoded private key byte slice
func ReadPrivatePKCS8(path string) ([]byte, error) {
	key, err := readPrivate(path)
	if err != nil {
		return nil, err
	}

	return encodePrivateKey(key, pkcs8)
}

// ReadPublicPKCS1 reads a public key PEM file and returns a PKCS1 encoded public key byte slice
func ReadPublicPKCS1(path string) ([]byte, error) {
	key, err := readPublic(path)
	if err != nil {
		return nil, err
	}

	return encodePublicKey(key, pkcs1)
}

// ReadPublicPKIX reads a public key PEM file and returns a PKIX encoded public key byte slice
func ReadPublicPKIX(path string) ([]byte, error) {
	key, err := readPublic(path)
	if err != nil {
		return nil, err
	}

	return encodePublicKey(key, pkix)
}

// GetPrivateKey generates an RSA private key struct of the given bit size
func GetPrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bitSize)
}

// GetPKCS1PrivateKey generates an RSA private key and returns the PKCS1 byterepresentation of the PEM block
func GetPKCS1PrivateKey(bitSize int) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	return encodePrivateKey(privateKey, pkcs1)
}

// GetPKCS8PrivateKey generates an RSA private key and returns the PKCS8 byterepresentation of the PEM block
func GetPKCS8PrivateKey(bitSize int) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	return encodePrivateKey(privateKey, pkcs8)
}

// GetPKCS1PrivateKeyString returns the PKCS1 byterepresentation of a given RSA private key struct
func GetPKCS1PrivateKeyString(privateKey *rsa.PrivateKey) ([]byte, error) {
	return encodePrivateKey(privateKey, pkcs1)
}

// GetPKCS8PrivateKeyString returns the PKCS8 byterepresentation of a given RSA private key struct
func GetPKCS8PrivateKeyString(privateKey *rsa.PrivateKey) ([]byte, error) {
	return encodePrivateKey(privateKey, pkcs8)
}

// GetPKCS1PublicKeyString returns the PKCS1 byterepresentation of a given RSA public key struct
func GetPKCS1PublicKeyString(publicKey *rsa.PublicKey) ([]byte, error) {
	return encodePublicKey(publicKey, pkcs1)
}

// GetPKIXPublicKeyString returns the PKIX byterepresentation of a given RSA public key struct
func GetPKIXPublicKeyString(publicKey *rsa.PublicKey) ([]byte, error) {
	return encodePublicKey(publicKey, pkix)
}

// GeneratePKCS1PrivateKey generates a new private key of the given bit size,
// writes it as PKCS1 PEM file to disc, and returns the RSA private key struct
func GeneratePKCS1PrivateKey(path string, bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	err = writePrivateKey(path, privateKey, pkcs1)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GeneratePKCS8PrivateKey generates a new private key of the given bit size,
// writes it as PKCS8 PEM file to disc, and returns the RSA private key struct
func GeneratePKCS8PrivateKey(path string, bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	err = writePrivateKey(path, privateKey, pkcs8)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GeneratePKCS1Keypair generates a new private key of the given bit size,
// writes its private key part with '.pem' suffix as PKCS1 PEM file to disc,
// writes its public key part with '.pub' suffix as PKIX PEM file to disc,
// and returns the RSA private key struct
func GeneratePKCS1Keypair(path, keyname string, bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	err = writePrivateKey(
		fmt.Sprintf("%s/%s.%s", path, keyname, privateSuffix),
		privateKey,
		pkcs1,
	)
	if err != nil {
		return nil, err
	}

	err = writePublicKey(
		fmt.Sprintf("%s/%s.%s", path, keyname, publicSuffix),
		&privateKey.PublicKey,
		pkix,
	)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GeneratePKCS8Keypair generates a new private key of the given bit size,
// writes its private key part with '.pem' suffix as PKCS8 PEM file to disc,
// writes its public key part with '.pub' suffix as PKIX PEM file to disc,
// and returns the RSA private key struct
func GeneratePKCS8Keypair(path, keyname string, bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	err = writePrivateKey(
		fmt.Sprintf("%s/%s.%s", path, keyname, privateSuffix),
		privateKey,
		pkcs8,
	)
	if err != nil {
		return nil, err
	}

	err = writePublicKey(
		fmt.Sprintf("%s/%s.%s", path, keyname, publicSuffix),
		&privateKey.PublicKey,
		pkix,
	)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// WritePKCS1PrivateKey writes a given RSA private key as PKCS1 PEM block to disc
func WritePKCS1PrivateKey(privateKey *rsa.PrivateKey, path string) error {
	return writePrivateKey(path, privateKey, pkcs1)
}

// WritePKCS8PrivateKey writes a given RSA private key as PKCS8 PEM block to disc
func WritePKCS8PrivateKey(privateKey *rsa.PrivateKey, path string) error {
	return writePrivateKey(path, privateKey, pkcs8)
}

// WritePKCS1PublicKey writes the public key part of a given RSA private key as PKCS1 PEM block to disc
func WritePKCS1PublicKey(publicKey *rsa.PublicKey, path string) error {
	return writePublicKey(path, publicKey, pkcs1)
}

// WritePKIXPublicKey writes the public key part of a given RSA private key as PKIX PEM block to disc
func WritePKIXPublicKey(publicKey *rsa.PublicKey, path string) error {
	return writePublicKey(path, publicKey, pkix)
}
