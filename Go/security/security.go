/*
        Created by: Tejashwi Kalp Taru
                    https://github.com/tejashwikalptaru

        License:    MIT, https://opensource.org/licenses/MIT

        *****************************************************************************
                RSA is suited to key encipherment, not bulk data encryption.
        *****************************************************************************
        Keeping this in mind I have designed the following code to encrypt/decrypt
        the message using AES and AES key will be encrypted/decrypted using RSA

        The idea is to implement a secure way for an Android application to send
        data to server and server will send secured data to Android application.

        (Android will use public key, server will use private key)

        Android:
            1. Will create a secure random key for AES
            2. Using the key, it will encrypt the payload
            3. The key will be then encrypted using public key (RSA)
            4. Finally the encrypted key and encrypted payload will be sent to server

        Server:
            1. Server will receive the encrypted key and payload
            2. Decrypt the encrypted key using private key (RSA)
            3. Decrypt the encrypted payload using the decrypted key
            4. Use the decrypted payload
            5. Create a random AES key
            6. Using the key server will encrypt the response
            7. The random AES key will be then encrypted using private key (RSA)
            8. Server will reply back both the encrypted key and encrypted response

        Android:
            1. Android will receive the encrypted key and response
            2. Encrypted key will be decrypted using public key (RSA)
            3. Using the decrypted key, the response will be decrypted
            4. Use the response
*/

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
		"crypto"
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

func RSA_Encrypt(message []byte, privateKeyPath string) ([] byte, error){
	priv, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	//Requires Golang 1.3 or above
	out, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.Hash(0), nil)

	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt message: %s", err)
	}

	return out, nil
}

func RSA_Decrypt(cipher []byte, privateKeyPath string) ([] byte, error){

	priv, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	// Decrypt the data
	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt message: %s", err)
	}

	return out, nil
}
