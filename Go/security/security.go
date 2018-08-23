package security

import (
	"crypto/aes"
	"io/ioutil"
	"fmt"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/rand"
)

//Decrypt the AES 128, ECB data
func DecryptAes128Ecb(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

//Reads the RSA private key from path
func readPrivateKey(path string) (*rsa.PrivateKey, error){
	// Read the private key
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Error read key file : %s", err)
	}

	// Extract the PEM-encoded data block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("Bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return nil, fmt.Errorf("Unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Bad private key: %s", err)
	}

	return priv, nil
}

//func RSA_Encrypt(message []byte, privateKeyPath string) ([] byte, error){
//
//}

func RSA_Decrypt(cipher []byte, privateKeyPath string) ([] byte, error){

	priv, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	// Decrypt the data
	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %s", err)
	}

	return out, nil
}
