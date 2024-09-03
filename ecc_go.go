package ecc_go

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// Function to generate ECDSA keys
func generateECDSAKeys() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Function to save a private key to a PEM file
func savePrivateKeyToPEM(fileName string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	return ioutil.WriteFile(fileName, pemData, 0600)
}

// Function to save a public key to a PEM file
func savePublicKeyToPEM(fileName string, key *ecdsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	return ioutil.WriteFile(fileName, pemData, 0644)
}

// Function to load a private key from a PEM file
func loadPrivateKeyFromPEM(fileName string) (*ecdsa.PrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// Function to load a public key from a PEM file
func loadPublicKeyFromPEM(fileName string) (*ecdsa.PublicKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		return pubKey, nil
	default:
		return nil, fmt.Errorf("not ECDSA public key")
	}
}

// Encrypt message using ECIES
func encryptMessage(publicKey *ecdsa.PublicKey, message []byte) ([]byte, error) {
	eciesPublicKey := ecies.ImportECDSAPublic(publicKey)
	return ecies.Encrypt(rand.Reader, eciesPublicKey, message, nil, nil)
}

// Decrypt message using ECIES
func decryptMessage(privateKey *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	eciesPrivateKey := ecies.ImportECDSA(privateKey)
	return eciesPrivateKey.Decrypt(ciphertext, nil, nil)
}
