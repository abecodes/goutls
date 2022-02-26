package rsakys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
)

func readFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cntnt, err := io.ReadAll(io.LimitReader(f, tenKB))
	if err != nil {
		return nil, err
	}

	return cntnt, nil
}

func readPrivate(p string) (*rsa.PrivateKey, error) {
	key, err := readFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(key)

	if block.Type != privateType {
		return nil, errWrongPrivateType
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil { // note this returns type `interface{}`
			return nil, err
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errParse
	}

	return privateKey, nil
}

func readPublic(p string) (*rsa.PublicKey, error) {
	key, err := readFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(key)

	if block.Type != publicType {
		return nil, errWrongPublicType
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var publicKey *rsa.PublicKey
	var ok bool
	publicKey, ok = parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errParse
	}

	return publicKey, nil
}
