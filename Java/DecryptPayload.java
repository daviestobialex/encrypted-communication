import java.io.File;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;

class DecryptPayload{
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

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            //decrypt the AES key
            String aesKey = "hTirgMbxScU8IZNWCx5LzHMOlZ3SE7dA3g1HZrjJKL2LuSTbMMs6rtWlutUkQx8jhafEeb0/DHF7d6uDXFG41BGh2iVi1Su+GqB14Spm5kAdmkFT3tehg+BQq2l/EEL0oikXGmwHA2TZ4y6DyL+NYPTwicnwu8/82GHLOB0fbOeoVJ4Cfn6GFBsMWJpOxTwxacdpbyWydfPyo/D53DomSN5KGy7fvl5EOq3nxO6s5tSkxoOmlRGdCEoHrrYn2rS8UjphBd3FqJmG24Z/KwDLwbKXRkPHWXoXJkP8lhWMDVj3A2UqVy0WhpxM19nqr6gXEH3SGJlPBgcGAh+J6ke0YYzpOHF1UDWHvzFxXWa2ZE038H727/iBsTTqoFdxJro2Ai8bU8D8YODBMo4zSH5j0BsC/mrauux7n5jGSSA6JSs81g3pc/ZLoQgzTgvu2a8CBxV6dBIBQCweF8wPoftfn816w/9t/kFTrlfk6OEmkLow6dHXeU2bBqWSN99xlVxqyN44plEOe1MdBLmfppix2s9V5LvvlpjtI/ttmjtq8an4878OqvmfQCYpCkoTNAMSC42+p1GVgO4+KAc8QieR+lYTgdaXXZQCrwYLLlFkW22POqZmtFbKh44bD5yl/wtSROBLiS+QQ5UhZYBycxeEMdW4Fvyi/U3ASafI+MJxADE=";

            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKey.getBytes());
            byte[] decryptedKeyBytes = cipher.doFinal(aesKeyBytes);
            String decryptedKey = new String(decryptedKeyBytes);
            System.out.println("Decrypted AES Key: " + decryptedKey);

            //Now using the decrypted AES key, decrypt the response
            String response = "+IN874ZSUnLXAFA6WXHpP1A82FS4QN2V1RR6vUir8g0=";

            byte[] responseBytes = Base64.getDecoder().decode(response.getBytes());
            SecretKeySpec skey = new SecretKeySpec(decryptedKey.getBytes(), "AES");
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, skey);
            byte[] decryptedResponseBytes = aesCipher.doFinal(responseBytes);
            String decryptedResponse = new String(decryptedResponseBytes);
            System.out.println("Decrypted Text: " + decryptedResponse);

        } catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
}