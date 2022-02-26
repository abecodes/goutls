package rsakys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func getPrivateKeyBlock(key *rsa.PrivateKey, format pemFormat) ([]byte, error) {
	var block []byte

	switch format {
	case pkcs1:
		block = x509.MarshalPKCS1PrivateKey(key)
		if len(block) == 0 {
			return nil, errParse
		}
	case pkcs8:
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		block = b
	default:
		return nil, errParse
	}

	return block, nil
}

func getPublicKeyBlock(key *rsa.PublicKey, format pemFormat) ([]byte, error) {
	var block []byte

	switch format {
	case pkcs1:
		block = x509.MarshalPKCS1PublicKey(key)
		if len(block) == 0 {
			return nil, errParse
		}
	case pkix:
		b, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		block = b
	default:
		return nil, errParse
	}

	return block, nil
}

func encodePrivateKey(key *rsa.PrivateKey, format pemFormat) ([]byte, error) {
	block, err := getPrivateKeyBlock(key, format)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  privateType,
		Bytes: block,
	}), nil
}

func encodePublicKey(key *rsa.PublicKey, format pemFormat) ([]byte, error) {
	block, err := getPublicKeyBlock(key, format)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  publicType,
		Bytes: block,
	}), nil
}

func writePrivateKey(path string, key *rsa.PrivateKey, format pemFormat) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := getPrivateKeyBlock(key, format)
	if err != nil {
		return err
	}

	return pem.Encode(file, &pem.Block{
		Type:  privateType,
		Bytes: block,
	})
}

func writePublicKey(path string, key *rsa.PublicKey, format pemFormat) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := getPublicKeyBlock(key, format)
	if err != nil {
		return err
	}

	return pem.Encode(file, &pem.Block{
		Type:  publicType,
		Bytes: block,
	})
}
