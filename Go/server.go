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
	"log"
		"fmt"
	"encoding/base64"
	"github.com/encrypted-communication/Go/security"
)



func main(){
	//sample message from mobile application
	cipherKey := "gm8NWjXoZOej9cg/kthHTBLFKEqRESvWN3Ky+gAEvod8wq4vJQ513YMUx2IZ9OQ36lc2PhJfWRA1hPC6Zl2nZab4C8kg6xVH9ZOZ5Hmsc1qJvfmcfrgYk2RypkARH28k1QD8wBcp9E4e/VFK3hPu141Dv73s0VKj6+Gkxq6pgm8r9/BA7UrMT7uQw5gy1vyCG7r5hLtfa+z5fw9+Y4awbAwWz/fikTQqKnaer30DwxeSN5KGuucxRBald8Pb8m70V0mLZskwIlI5Pbc2YSCfZzzeyUkQKg2+zP7P7Bh+GSmmd+eHuXsQHf3+n1WRdAODL5zVT8m+bO/Y7vq/a4/t3NCTAlBG3VV4Bf18F1seZAJgfIL/11a/Nciv2Yj9Z1mH9v867wINowBBnuMcnYfz5d8HDo5bK6ReKI2oz9Am7L1Gjjt9AqJFI6Jv4IpoerEgLWP/sokiPMY2qBa1Qg5zGB8U//kP9jjedeZ6cg54DYFZ/HqipETrz3+uQA7sGo18JMYAgXQZQnJ9W3lm9WfaOKydRMVPdqkNhkd6h3Z6ou0tZFFMuliUyvRKt+UFpVpja3K1/OZihIOf7njriGtSVZvMa0i5j4UYOowrT37M+JfEmdEkt8GtfJFnqWe8qyhFlkSd/an8NC7MphmuDhcH+kAsR5UgDUHW0g/djL7lOsc="

	cipherMessage := "H7oKxS/RlZJmNzP6bEW33HivU+Pq9T7p6b+BETlXZT4fGxqPwgMoenM/oOmiBKtbuhlvnH64bhzl9CbkhTHZfRf6Fs8m85Ef9NaFI740jn1GSactI5Yl8c8FrY2ZConv"

	//decrypt the cipherKey using RSA public key to gain AES key
	cipherKeyByte, _ := base64.StdEncoding.DecodeString(cipherKey)
	aesKey, err := security.RSA_Decrypt(cipherKeyByte, "../Keypair/go_compatible_private.pem")
	if err != nil {
		log.Fatal(err)
	}

	//AES decrypt the cipher message using decrypted key
	cipherMessageByte, _ := base64.StdEncoding.DecodeString(cipherMessage)
	originalMessageByte := security.DecryptAes128Ecb([]byte(cipherMessageByte), aesKey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Decrypted Message: " + string(originalMessageByte))

	//now let's encrypt a message using AES


}
