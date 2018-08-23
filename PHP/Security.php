<?php
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

        TODO: Will replace the depricated mcrypt with OpenSSL in future 🧐
    */

    class Security{
        function __construct(){
            if(!function_exists('mcrypt_decrypt')) {
                die('mcrypt is missing, required for this script to run');
            }
            if (!extension_loaded('openssl')) {
                // no openssl extension loaded.
                die('OpenSSL is required for this script to run');
            }
        }

        //Generates a private and public key file for RSA 4096
        public function RSA_Generate(){
            $config = array(
                "digest_alg" => "sha512",
                "private_key_bits" => 4096,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            );
            $keys = openssl_pkey_new($config);
            $priv = openssl_pkey_get_private($keys);
            openssl_pkey_export_to_file($priv, 'private.pem');
            if(function_exists('exec')) {
                exec("openssl rsa -in private.pem -pubout -outform DER -out public.der");
                return true;
            } else {
                throw new Exception("Private key generated, run the following command to generate public key: openssl rsa -in private.pem -pubout -outform DER -out public.der");
            }
        }

        //Encrypt the given message using RSA, private key
        public function RSA_Encrypt($keyPath, $message){
            $fp = fopen($keyPath, "r");
            if($fp){
                $privateKey = fread($fp, filesize($keyPath));
                fclose($fp);
                $res = openssl_get_privatekey($privateKey);
                if(openssl_private_encrypt($message, $cipher, $res, OPENSSL_PKCS1_PADDING ) ){
                    return $cipher;
                } else {
                    throw new Exception('Unable to encrypt the message');
                }
            } else {
                throw new Exception('Unable to read the private key file');
            }
        }

        //decrypt the message using RSA, private key
        public function RSA_Decrypt($keyPath, $cipher){
            $fp = @fopen($keyPath, "r");
            if($fp){
                $privateKey = fread($fp, filesize($keyPath));
                @fclose($fp);
                $res = openssl_get_privatekey($privateKey);
                if(openssl_private_decrypt($cipher, $decrypted, $res, OPENSSL_PKCS1_OAEP_PADDING ) ){
                    return $decrypted;
                } else {
                    throw new Exception('Unable to decrypt the cipher');
                }
            } else {
                throw new Exception('Unable to read the private key file');
            }
        }

        //Generates a random key that can be used for AES encryption
        public function AES_Keygen(){
            return bin2hex(openssl_random_pseudo_bytes(16)); //128 bit
        }

        //Encrypt message using key, uses AES
        public function AES_Encrypt($input, $key) {
            $size = @mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB); 
            $input = $this->pkcs5_pad($input, $size); 
            $td = @mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, ''); 
            $iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND); 
            @mcrypt_generic_init($td, $key, $iv); 
            $data = @mcrypt_generic($td, $input); 
            @mcrypt_generic_deinit($td); 
            @mcrypt_module_close($td); 
            return $data; 
        } 

        //Function to pad the given message using blocksize, PKCS5 padding
        private function pkcs5_pad ($text, $blocksize) { 
            $pad = $blocksize - (strlen($text) % $blocksize); 
            return $text . str_repeat(chr($pad), $pad); 
        } 

        //Decrypt AES message using key
        public function AES_Decrypt($sStr, $sKey) {
            $decrypted= @mcrypt_decrypt(
                MCRYPT_RIJNDAEL_128,
                $sKey, 
                $sStr, 
                MCRYPT_MODE_ECB
            );
            $dec_s = strlen($decrypted); 
            $padding = ord($decrypted[$dec_s-1]); 
            $decrypted = substr($decrypted, 0, -$padding);
            return $decrypted;
        }
    }
?>