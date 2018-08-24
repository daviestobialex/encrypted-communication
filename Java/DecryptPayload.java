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
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

class DecryptPayload{
    public static String AES_256_Decrypt(byte[] inputBytes, String key){
        //extract iv and contents from input bytes
        byte[] ivBytes = Arrays.copyOfRange(inputBytes, 0, 16);
        byte[] contentBytes = Arrays.copyOfRange(inputBytes, 16, inputBytes.length);

        try {
            Cipher ciper = Cipher.getInstance("AES/CBC/PKCS5Padding");

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(),"AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes,0, ivBytes.length);

            ciper.init(Cipher.DECRYPT_MODE, keySpec, iv);
            return new String(ciper.doFinal(contentBytes));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static String RSA_Decrypt(String publicKeyPath, byte[] cipherMessage){
        try{
            File pubKeyFile = new File(publicKeyPath);
            DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
            byte[] keyBytes = new byte[(int) pubKeyFile.length()];

            dis.readFully(keyBytes);
            dis.close();

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            byte[] decryptedCipher = cipher.doFinal(cipherMessage);
            String plainMessage = new String(decryptedCipher);
            return plainMessage;
        } catch (Exception e){
            System.out.println(e.getMessage());
            return null;
        }
    }


    public static void main(String[] args){
        try{
            //decrypt the AES key
            String aesKey = "nHUC/96g0OPwNJrXX7HC919VLt+4eTrTwoyT1RU0bDb1zxbpLjQL/lQxfwho5+O4LeJyi5fxrsI+4/LUscMSvi1UOI2M1TXYDxM6qBoeBghCOxCf3Alp7PURAlcy3dHM88Id0DmPLY/jS9G/xLPomUF6aN+j7m30UAHC/cvWxJT0t2NHSi6oMGux1H8yWN9lnh8OK4UC5YQOZCtUt2EO3PLd2ylFFTXJKUgi4bIEOwz3VqnfdXhvaB9+2okyOFdLodwqA2okPSi7Qd2wp9WXhBVXJG2j0L53301Y6E70S+0BOEY9qYAxEHJWP11ZwewHq4yEE2pK4S0qwTrjcmLcwoEaHawgZPDpCzObCMdZCwnFuOc+q+lWwuWDSqqa8CjOPme9BPKuUrr15lXt9ZOU/vP09Q0521AdBPAI2heXc3NbgQJALUd2F6lNi728/SeB8IOQmFKZCSvrLfi8Db8Mne1eqnZFbwXKpjxW69FiKfgZgM/IOj7nPwFPX41iboVVdLMygrXJvoZway+Rxje+7sEIqVhffgIt3GxRuA9lGSKHH+TJmAYG2+6fDK2O93fw4wKNeLQiwC0012h1ElbqFyEA1jyue2WnPqnDne8zwWLZ/ZrSSEnyWdVp2pi7GPXFBrpkKSbOSYpTeYW9MprCq+fDHaf//4NSn8SCt0PUr6E=";

            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKey.getBytes());
            String decryptedKey = RSA_Decrypt("../Keypair/public.der", aesKeyBytes);
            
            System.out.println("Decrypted AES Key: " + decryptedKey);

            //Now using the decrypted AES key to decrypt the response
            String response = "J3tyG4s/VY2sJYZoyb/xmNRXezLTAvZiTmbDLo7awERDwFzgc3+Z2XzjTVJKUbMR";

            byte[] responseByte = Base64.getDecoder().decode(response.getBytes());
            String output = AES_256_Decrypt(responseByte, decryptedKey);
            System.out.println("CBC Output: " + output);

        } catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
}