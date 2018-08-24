# Server side codes

**Note**

The server will be using private RSA keys for encryption and decryption, and hence message from one server should not be decrypted on another server. (Because server will use private key to encrypt, and if another server will try to decrypt the message with private key it will fail). Message from server will be decrypted on mobile side with the help of public key