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
    */

    showErrors(true);

    include 'Security.php';
    $security = new Security();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $_POST = $data = file_get_contents('php://input');
        if($_POST){
            $_POST = json_decode($_POST, true);
            if( isset($_POST['cipher_key']) && isset($_POST['cipher_value']) ){
                $cipherKey = $_POST['cipher_key'];
                $cipherValue = $_POST['cipher_value'];
    
                //Decrypt the encrypted AES key using RSA
                $decryptedKey = $security->RSA_Decrypt("private.pem", base64_decode($cipherKey));
                if($decryptedKey){
                    $decryptedValue = $security->AES_Decrypt(base64_decode($cipherValue), $decryptedKey);
                    //perform some operation on your decrypted value, and then finally send the response

                    $aes_key = $security->AES_Keygen();
                    $response = "Hi, I am your little server";
                    $cipher_value = $security->AES_Encrypt($response, $aes_key);
                    $cipher_key = $security->RSA_Encrypt("private.pem", $aes_key);
                    $reply = array(
                        'your_message' => $decryptedValue,
                        'cipher_key' => base64_encode($cipher_key),
                        'cipher_value' => base64_encode($cipher_value),
                        'response_code' => 200
                    );
                    sendResponse($reply, 200);
                } else {
                    sendResponse(array('status' => 'Unable to decrypt the cipher', 'response_code' => 403), 403);
                }
            } else {
                sendResponse(array('status' => 'Missing keys from payload', 'response_code' => 400), 400);
            }
        } else {
            sendResponse(array('status' => 'Missing payload', 'response_code' => 400), 400);
        }
    } else {
        die('Welcome to my little server 😎');
    }

    function sendResponse($data, $responseCode){
        header('Content-Type: application/json');
        http_response_code($responseCode);
        echo json_encode($data);
    }

    function showErrors($show){
        if($show){
            error_reporting(E_ALL);
            @ini_set('display_errors', 1);
        } else {
            error_reporting(0);
            @ini_set('display_errors', 0);
        }
    }	
?>