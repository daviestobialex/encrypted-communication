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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)

func pKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func aesKeygen(length int) ([]byte, error) {
	iv := make([]byte, length)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Error: %s, N: ", err)
	}
	return iv, nil
}

//AESKeygen : Generate a random key for AES
func AESKeygen(length int) ([]byte, error) {
	iv := make([]byte, length)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("Error: %s, N: ", err)
	}
	key := base64.StdEncoding.EncodeToString(iv)
	return []byte(key), nil
}

//EncryptAES256CBC : Encrypt the message using AES CBC 256
func EncryptAES256CBC(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := plaintext

	b = pKCS5Padding(b, aes.BlockSize, len(plaintext))
	ciphertext := make([]byte, len(b))
	iv, _ := aesKeygen(aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, b)
	final := append(iv, ciphertext...)
	return final, nil
}

//DecryptAES256CBC : Decrypt the data using AES CBC 256
func DecryptAES256CBC(key []byte, ciphertext []byte) ([]byte, error) {
	var block cipher.Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	return pKCS5UnPadding(ciphertext), nil
}

//Reads the RSA private key from path
func readPrivateKey(path string) (*rsa.PrivateKey, error) {
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

//RSADecrypt : Decrypt the given cipher bytes using private key
func RSADecrypt(cipher []byte, privateKeyPath string) ([]byte, error) {
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

//RSAEncrypt : Encrypts the given message using private key
func RSAEncrypt(message []byte, privateKeyPath string) ([]byte, error) {
	priv, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return privateEncrypt(priv, message)
}

//Taken from https://stackoverflow.com/a/19621035/2520628
//Credit goes to: artyom
func privateEncrypt(priv *rsa.PrivateKey, data []byte) (enc []byte, err error) {

	var (
		errInputSize  = errors.New("input size too large")
		errEncryption = errors.New("encryption error")
	)

	k := (priv.N.BitLen() + 7) / 8
	tLen := len(data)
	// rfc2313, section 8:
	// The length of the data D shall not be more than k-11 octets
	if tLen > k-11 {
		err = errInputSize
		return
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], data)
	c := new(big.Int).SetBytes(em)
	if c.Cmp(priv.N) > 0 {
		err = errEncryption
		return
	}
	var m *big.Int
	var ir *big.Int
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}
	enc = m.Bytes()
	return
}
