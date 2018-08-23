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
