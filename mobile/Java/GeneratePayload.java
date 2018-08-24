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

import java.io.File;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

class GeneratePayload{
    public static String RSA_Encrypt(String publicKeyPath, byte[] message){
        try{
            File pubKeyFile = new File(publicKeyPath);
            DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
            byte[] keyBytes = new byte[(int) pubKeyFile.length()];

            dis.readFully(keyBytes);
            dis.close();

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = Base64.getEncoder().encode(cipher.doFinal(message));
            String encryptedMessage = new String(encryptedBytes);
            return encryptedMessage;

        } catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static String AES_256_Encrypt(byte[] message, SecretKey key){
        try{
            // Generating IV.
            int ivSize = 16;
            byte[] iv = new byte[ivSize];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            //encrypt the message
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(message);

            //combine IV and encrypted message
            byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
            System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
            System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

            byte[] encryptedFinal = Base64.getEncoder().encode(encryptedIVAndText);
            return new String(encryptedFinal);
        } catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static void main(String[] args){
        try{
            String payload = "A simple payload, you can also send JSON and use them as your need on server side";

            //Generate key for AES encryption
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256); // The AES key size in number of bits
            SecretKey secKey = generator.generateKey();
            
            String encryptedPayload = AES_256_Encrypt(payload.getBytes(), secKey);

            //encrypt the AES secret key using RSA
            String encryptedKey = RSA_Encrypt("../../keypair/public.der", secKey.getEncoded());

            System.out.println("Encrypted Text: " + encryptedPayload);
            System.out.println("Encrypted AES Key: " + encryptedKey);

        } catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
}