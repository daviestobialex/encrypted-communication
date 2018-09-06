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

package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/encrypted-communication/server/Go/security"
)

func main() {
	//RSA encrypted AES key
	cipherKey := "jhGGVwMV/U7vl4qlczlyUOKurF1QJOF1fLgQYcOnvcdf9UjNg43K1fWpaNmv3u9Xsbtf7IxQd21l7LI9qJdnrM5Um9B+C9eduhThOuBPjxA0wZJwm20GLTtniTqHpsJZtKfEhoVeoTLz8DP7NEBSCEuwD6veJf/861q7oBbZglNDhoOaluplz8/UBvqozXeo/27uKFZ4IDAao3w7wPwlunsFI6J2kPFv9fnUkoLtUxxCZ27vejWbKA15v/UO5S0rhTWaEHB6SeLHF9rvJTX/MAWXneO2gxi1XSW4L/j0Met4oLp5yCSAHBZ0yMqtXn/Ssu0cjkD34Q9Aj+JtwEv6mrQC1RxSd1IZJ3HUyMTzQNnuqiV7s4v+leaLpnxbWBIgXoj889kpNh5oulN0Y6jj3tnk2FB0/agY2bQDCARL+irYa3fWwrvGgZb8My1WQvTebFfbRyZcpnO7eLsypCV4QdK6o/NMNLFRGmjZv254EUr8n5cxoN/euZ9i0Vjx8WeKOpKLayGxZAYB6c0p1YksfGaOMCIvvEu03YToxHyZcAtFBxMvHtcQag1zDsuAGKv+ABG3igxO7Xwcm6fbu/44E0gBF2PXg9xDX6EyS/PdONWwrL3ObReNQI+zuhsDCacBwhbhPh8HspxVOedD32IUvfd0TbOntRhwTqnZ2xKGExA="

	//AES encrypted message
	cipherMessage := "VsfdnLS7BJznflSQeLVMBSJk+agp1jf4PeLMIOf/C47a/armSwB1ZaSaOnxhFF4uekVz8T6subSbyvLI68luNc7hQEokXF8a08aOd8IN7GwwDZsO8hFeAuuwvtyP7PdKyyPQPX2uT1gd/hTnr73Oag=="

	//decrypt the cipherKey using RSA private key to gain AES key
	cipherKeyByte, _ := base64.StdEncoding.DecodeString(cipherKey)
	aesKey, err := security.RSADecrypt(cipherKeyByte, "../../keypair/go_compatible_private.pem")
	if err != nil {
		log.Fatal(err)
	}

	//AES decrypt the cipher message using decrypted key
	cipherMessageByte, _ := base64.StdEncoding.DecodeString(cipherMessage)
	originalMessageByte, err := security.DecryptAES256CBC(aesKey, cipherMessageByte)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Decrypted Message: " + string(originalMessageByte))

	//now prepare a reply back for mobile side
	reponse := "Hi, I am your little server"

	//encrypt the message using AES
	key, _ := security.AESKeygen(16)
	encryptedByte, err := security.EncryptAES256CBC(key, []byte(reponse))
	if err != nil {
		log.Fatal(err)
	}
	encrypted := base64.StdEncoding.EncodeToString(encryptedByte)

	fmt.Println("aes_value: " + encrypted)

	//now encrypt the AES key using RSA private key
	keyBytes, err := security.RSAEncrypt(key, "../../keypair/go_compatible_private.pem")
	if err != nil {
		log.Fatal(err)
	}

	encryptedKey := base64.StdEncoding.EncodeToString(keyBytes)

	fmt.Println("aes_key: " + encryptedKey)
}
