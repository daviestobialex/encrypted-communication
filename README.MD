# Secure communication between Mobile and Server (RSA-4096/AES-256-CBC) 😎

**Abstract**

The goal is to create a secure communication between an android application and server using RSA. We know that RSA is not meant for bulk data encryption, and hence we have introduced AES to encrypt the data and RSA to encrypt the AES key.

**Flow**

- Android:
    1. Will create a secure random key for AES
    2. Using the key, it will encrypt the payload
    3. The key will be then encrypted using public key (RSA)
    4. Finally the encrypted key and encrypted payload will be sent to server

- Server:
    1. Server will receive the encrypted key and payload
    2. Decrypt the encrypted key using private key (RSA)
    3. Decrypt the encrypted payload using the decrypted key
    4. Use the decrypted payload
    5. Create a random AES key
    6. Using the key server will encrypt the response
    7. The random AES key will be then encrypted using private key (RSA)
    8. Server will reply back both the encrypted key and encrypted response

- Android:
    1. Android will receive the encrypted key and response
    2. Encrypted key will be decrypted using public key (RSA)
    3. Using the decrypted key, the response will be decrypted
    4. Use the response

**TODO**

- ~~Need to replace the depricated mcrypt PHP function with OpenSSL~~
- Create an Android application 
- Add server side scripts for ~~Go~~, Node, Python, C# and Ruby

**Files**
- [server.php](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/PHP/server.php)
    - This file contains the PHP side server logic for request receiving and response, uses [Security.php](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/PHP/Security.php)
- [DecryptPayload.java](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Java/DecryptPayload.java)
    - A simple Java source code to decrypt the encrypted server response
- [GeneratePayload.java](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Java/GeneratePayload.java)
    - A simple Java source code to generate the encrypted message which will be processed by server.
- [private.pem](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Keypair/private.pem)
    - A dummy RSA private key file
- [public.der](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Keypair/public.der)
    - A dummy RSA public key file
- [go_compatible_private.pem](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Keypair/go_compatible_private.pem)
    - A dummy RSA private key file (Compatible with Go lang, see this issue [x509.ParsePKCS1PrivateKey](https://groups.google.com/forum/#!topic/golang-nuts/ZZ1Wt9d268Q)
- [server.go](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Go/server.go)
    - A Go sample script to encrypt/decrypt the messages using RSA and AES, uses [security.go](https://github.com/tejashwikalptaru/encrypted-communication/blob/master/Go/security/security.go)

**Sample Output**
- GeneratePayload.java
    > Encrypted Text: H7oKxS/RlZJmNzP6bEW33HivU+Pq9T7p6b+BETlXZT4fGxqPwgMoenM/oOmiBKtbuhlvnH64bhzl9CbkhTHZfRf6Fs8m85Ef9NaFI740jn1GSactI5Yl8c8FrY2ZConv

    > Encrypted AES Key: gm8NWjXoZOej9cg/kthHTBLFKEqRESvWN3Ky+gAEvod8wq4vJQ513YMUx2IZ9OQ36lc2PhJfWRA1hPC6Zl2nZab4C8kg6xVH9ZOZ5Hmsc1qJvfmcfrgYk2RypkARH28k1QD8wBcp9E4e/VFK3hPu141Dv73s0VKj6+Gkxq6pgm8r9/BA7UrMT7uQw5gy1vyCG7r5hLtfa+z5fw9+Y4awbAwWz/fikTQqKnaer30DwxeSN5KGuucxRBald8Pb8m70V0mLZskwIlI5Pbc2YSCfZzzeyUkQKg2+zP7P7Bh+GSmmd+eHuXsQHf3+n1WRdAODL5zVT8m+bO/Y7vq/a4/t3NCTAlBG3VV4Bf18F1seZAJgfIL/11a/Nciv2Yj9Z1mH9v867wINowBBnuMcnYfz5d8HDo5bK6ReKI2oz9Am7L1Gjjt9AqJFI6Jv4IpoerEgLWP/sokiPMY2qBa1Qg5zGB8U//kP9jjedeZ6cg54DYFZ/HqipETrz3+uQA7sGo18JMYAgXQZQnJ9W3lm9WfaOKydRMVPdqkNhkd6h3Z6ou0tZFFMuliUyvRKt+UFpVpja3K1/OZihIOf7njriGtSVZvMa0i5j4UYOowrT37M+JfEmdEkt8GtfJFnqWe8qyhFlkSd/an8NC7MphmuDhcH+kAsR5UgDUHW0g/djL7lOsc= 
- Server Response:
    ```
    {
        "your_message": "A simple payload, you can also send JSON and use them as your need on server side",
        "cipher_key": "hTirgMbxScU8IZNWCx5LzHMOlZ3SE7dA3g1HZrjJKL2LuSTbMMs6rtWlutUkQx8jhafEeb0/DHF7d6uDXFG41BGh2iVi1Su+GqB14Spm5kAdmkFT3tehg+BQq2l/EEL0oikXGmwHA2TZ4y6DyL+NYPTwicnwu8/82GHLOB0fbOeoVJ4Cfn6GFBsMWJpOxTwxacdpbyWydfPyo/D53DomSN5KGy7fvl5EOq3nxO6s5tSkxoOmlRGdCEoHrrYn2rS8UjphBd3FqJmG24Z/KwDLwbKXRkPHWXoXJkP8lhWMDVj3A2UqVy0WhpxM19nqr6gXEH3SGJlPBgcGAh+J6ke0YYzpOHF1UDWHvzFxXWa2ZE038H727/iBsTTqoFdxJro2Ai8bU8D8YODBMo4zSH5j0BsC/mrauux7n5jGSSA6JSs81g3pc/ZLoQgzTgvu2a8CBxV6dBIBQCweF8wPoftfn816w/9t/kFTrlfk6OEmkLow6dHXeU2bBqWSN99xlVxqyN44plEOe1MdBLmfppix2s9V5LvvlpjtI/ttmjtq8an4878OqvmfQCYpCkoTNAMSC42+p1GVgO4+KAc8QieR+lYTgdaXXZQCrwYLLlFkW22POqZmtFbKh44bD5yl/wtSROBLiS+QQ5UhZYBycxeEMdW4Fvyi/U3ASafI+MJxADE=",
        "cipher_value": "+IN874ZSUnLXAFA6WXHpP1A82FS4QN2V1RR6vUir8g0=",
        "response_code": 200
    }
    ```
- DecryptPayload.java
    >Decrypted AES Key: 0162a5e5257306d67de8a83c51c7ce67
    
    > Decrypted Text: Hi, I am your little server


**Knowledge Base**
> This project uses RSA 4096, ~~AES 128 ECB~~ AES 256 CBC

> Private key is created using PHP OpenSSL

> To create public key (.der) use the command: openssl rsa -in private.pem -pubout -outform DER -out public.der

> You can convert the private.pem to Go compatible PEM using command: openssl rsa -in private.pem -out go_compatible_private.pem

**Contribution**

There is always room for improvement. 

I am thinking to add more and more client (mobile) and server languages for secure communication. Like in future I will keep on adding more server side languages, compatible encryption/decryption methods among them, add mobile apps like iOS, React Native, Windows Phone and others


This project is open for contribution, create a PR with detailed changes, or create a bug report
