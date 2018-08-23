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

class GeneratePayload{
    public static void main(String[] args){
        try{
            File pubKeyFile = new File("public.der");
            DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
            byte[] keyBytes = new byte[(int) pubKeyFile.length()];

            dis.readFully(keyBytes);
            dis.close();

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256); // The AES key size in number of bits
            SecretKey secKey = generator.generateKey();
            
            String payload = "A simple payload, you can also send JSON and use them as your need on server side";

            //encrypt the payload using AES
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
            byte[] byteCipherText = Base64.getEncoder().encode(aesCipher.doFinal(payload.getBytes()));
            String cipherText = new String(byteCipherText);

            //encrypt the AES secret key using RSA
            byte[] encryptedKeyBytes = Base64.getEncoder().encode(cipher.doFinal(secKey.getEncoded()));
            String encryptedKey = new String(encryptedKeyBytes);

            System.out.println("Encrypted Text: " + cipherText);
            System.out.println("Encrypted AES Key: " + encryptedKey);

        } catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
}