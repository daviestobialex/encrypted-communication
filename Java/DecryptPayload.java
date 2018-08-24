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
            String aesKey = "dhbBkYbVf1EBZLF8F+2rSbT6UGDTEfeyxZgSJb7KxX+S10ETKJvrH1+o/04gsb0nLJSjgfpJp92HRh2n6B//GhwhkVXAvucPrxZqo779mHiC1aiopSh6RAd2veM2bZLEr9fDsvc85vR0wXiaId6PaRU4ocqOjDWRXsy9xpYa3/G+9dmIun7SfsM98J5OnkqfasnrGOvRawdpF2BzVerswHWIsKTxZQqEScKU66I1mR0eiNQUwyc8bWS26Jquh1r7BnDPcjg5Rlw6KefcssQHi7D1HSpOTdKUnlT78yEbDs+vR2oAe74J6x8IYT4x94DPl2TAxY72bxavhTkGcZMtMnzcpGL92U+GspFyHckDIghGQGSJ3CjyddTU2WQS57EmxYT6hw6uw/1vAH4sq3wZSXXWJLdM7OdthDvXAnXgiQ9h6gURE2KMrRvBLUK4oUXL/GvwNlJn+UXM/CaHyJmOih71Bic/5WZ1toLnM6+i8dfkw/zpRd+TjCETqI3yAFwwpPcpq0WxWDXv1GngDbn2uLrViRxVJ6OUyXVo9MIaZxCamzwl1pb25GgKXTtQLPtP8agkBGaCTMHW5KZHv32oEOP14Wj+P+C0CRrAg9dKDv6B3dHLHBrLoZCgsOgDh0YYG0lVutTJba0nT9Omx997y6MGAFcJ+Ydf8WOuGpGMymk=";
            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKey.getBytes());
            String decryptedKey = RSA_Decrypt("../Keypair/public.der", aesKeyBytes);
            
            System.out.println("Decrypted AES Key: " + decryptedKey);

            //Now using the decrypted AES key, try to decrypt the response
            String response = "GlSrU2zLGvu99ERYvlzIUkNB+Ic22h7cLhdmNCo40wTzdRVAujlkSiYJU02iao37";

            byte[] responseByte = Base64.getDecoder().decode(response.getBytes());
            String output = AES_256_Decrypt(responseByte, decryptedKey);
            System.out.println("CBC Output: " + output);

        } catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
}