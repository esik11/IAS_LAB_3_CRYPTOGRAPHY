<?php

namespace Cryptography\ECC;

use RuntimeException;

class ECCCrypto
{
    private string $baseDir;
    private string $keysDir;
    private string $encryptedDir;
    private string $messagesDir;

    public function __construct(string $baseDir = ".")
    {
        $this->baseDir = rtrim($baseDir, '/');
        $this->keysDir = $this->baseDir . "/keys";
        $this->encryptedDir = $this->baseDir . "/encrypted";
        $this->messagesDir = $this->baseDir . "/messages";

        // Create directories if they don't exist
        foreach ([$this->keysDir, $this->encryptedDir, $this->messagesDir] as $dir) {
            if (!file_exists($dir)) {
                mkdir($dir, 0777, true);
            }
        }
    }

    /**
     * Generate ECC key pair using OpenSSL
     *
     * @param string $name User identifier
     * @return array Array containing paths to private and public key files
     */
    public function generateEccKeyPair(string $name = "user"): array
    {
        $privateKeyPath = "{$this->keysDir}/{$name}_private.pem";
        $publicKeyPath = "{$this->keysDir}/{$name}_public.pem";

        echo "\n🔐 Generating ECC key pair for " . ucfirst($name) . "...\n";

        // Generate private key
        $config = [
            "private_key_type" => OPENSSL_KEYTYPE_EC,
            "curve_name" => "secp256k1"
        ];

        $privateKey = openssl_pkey_new($config);
        if (!$privateKey) {
            throw new RuntimeException("Failed to generate private key: " . openssl_error_string());
        }

        // Export private key
        openssl_pkey_export_to_file($privateKey, $privateKeyPath);

        // Export public key
        $keyDetails = openssl_pkey_get_details($privateKey);
        file_put_contents($publicKeyPath, $keyDetails['key']);

        echo "✅ " . ucfirst($name) . "'s ECC key pair generated.\n";

        return [$privateKeyPath, $publicKeyPath];
    }

    /**
     * Encrypt message using ECIES
     *
     * @param string $message Message to encrypt
     * @param string $recipientPublicKeyPath Path to recipient's public key
     * @param string $sender Sender identifier
     * @return array Array containing paths to encrypted message and ephemeral public key
     */
    public function encryptMessage(string $message, string $recipientPublicKeyPath, string $sender = "jeorge"): array
    {
        $messagePath = "{$this->messagesDir}/{$sender}_message.txt";
        $encryptedMessagePath = "{$this->encryptedDir}/{$sender}_to_andrei_encrypted.bin";
        
        file_put_contents($messagePath, $message);

        // Generate ephemeral key pair
        $ephemeralPrivatePath = "{$this->encryptedDir}/ephemeral_private.pem";
        $ephemeralPublicPath = "{$this->encryptedDir}/ephemeral_public.pem";
        
        echo "\n🔑 " . ucfirst($sender) . " is generating an ephemeral key pair for message encryption...\n";
        
        [$ephemeralPrivatePath, $ephemeralPublicPath] = $this->generateEccKeyPair("ephemeral");

        // Derive shared secret using ECDH
        $sharedSecretPath = "{$this->encryptedDir}/shared_secret.bin";
        $this->deriveSharedSecret($ephemeralPrivatePath, $recipientPublicKeyPath, $sharedSecretPath);

        // Encrypt the message using AES-256-CBC with the derived key
        $this->encryptWithSharedSecret($messagePath, $encryptedMessagePath, $sharedSecretPath);

        return [$encryptedMessagePath, $ephemeralPublicPath];
    }

    /**
     * Decrypt ECIES-encrypted message
     *
     * @param string $encryptedMessagePath Path to encrypted message
     * @param string $ephemeralPublicPath Path to ephemeral public key
     * @param string $privateKeyPath Path to recipient's private key
     * @return string Decrypted message
     */
    public function decryptMessage(string $encryptedMessagePath, string $ephemeralPublicPath, string $privateKeyPath): string
    {
        echo "\n🔓 Decrypting the message using ECDH-derived key...\n";
        
        $sharedSecretPath = "{$this->encryptedDir}/shared_secret.bin";
        $this->deriveSharedSecret($privateKeyPath, $ephemeralPublicPath, $sharedSecretPath);

        $decryptedMessagePath = "{$this->messagesDir}/decrypted_by_andrei.txt";
        $this->decryptWithSharedSecret($encryptedMessagePath, $decryptedMessagePath, $sharedSecretPath);

        return file_get_contents($decryptedMessagePath);
    }

    /**
     * Perform ECDH key exchange
     *
     * @param string $privatePath Path to private key
     * @param string $publicPath Path to peer's public key
     * @param string $initiator Initiator identifier
     * @return string Binary shared secret
     */
    public function performECDH(string $privatePath, string $publicPath, string $initiator): string
    {
        echo "\n🔐 " . ucfirst($initiator) . " is performing ECDH key exchange...\n";
        
        $sharedSecretPath = "{$this->encryptedDir}/{$initiator}_shared_secret.bin";
        $this->deriveSharedSecret($privatePath, $publicPath, $sharedSecretPath);

        return file_get_contents($sharedSecretPath);
    }

    /**
     * Derive shared secret using ECDH
     */
    private function deriveSharedSecret(string $privateKeyPath, string $publicKeyPath, string $outputPath): void
    {
        $private = openssl_pkey_get_private("file://$privateKeyPath");
        $public = openssl_pkey_get_public("file://$publicKeyPath");

        if (!$private || !$public) {
            throw new RuntimeException("Failed to load keys: " . openssl_error_string());
        }

        $sharedSecret = openssl_pkey_derive($public, $private);
        if ($sharedSecret === false) {
            throw new RuntimeException("Failed to derive shared secret: " . openssl_error_string());
        }

        file_put_contents($outputPath, $sharedSecret);
    }

    /**
     * Encrypt data using shared secret
     */
    private function encryptWithSharedSecret(string $inputPath, string $outputPath, string $sharedSecretPath): void
    {
        $key = file_get_contents($sharedSecretPath);
        $iv = openssl_random_pseudo_bytes(16);
        $data = file_get_contents($inputPath);

        $encrypted = openssl_encrypt(
            $data,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        file_put_contents($outputPath, $iv . $encrypted);
    }

    /**
     * Decrypt data using shared secret
     */
    private function decryptWithSharedSecret(string $inputPath, string $outputPath, string $sharedSecretPath): void
    {
        $key = file_get_contents($sharedSecretPath);
        $data = file_get_contents($inputPath);
        
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);

        $decrypted = openssl_decrypt(
            $encrypted,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        file_put_contents($outputPath, $decrypted);
    }
} 