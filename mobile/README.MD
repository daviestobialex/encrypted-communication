# Mobile side codes

**Note**

The mobile side will be using public key to encrypt or decrypt messages, and server will be using private key to decrypt it.
Hence message from mobile app should not be decrypted on another mobile side app (because mobile will be using public key to encrypt message and another mobile will try to decrypt the message using public key and it will fail). Messages from mobile side will be decrypted on server side only.