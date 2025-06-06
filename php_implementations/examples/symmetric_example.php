<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Cryptography\Symmetric\SymmetricEncryption;

// Create instance of SymmetricEncryption
$crypto = new SymmetricEncryption();

// Basic encryption example
$message = "Hello, this is a secret message!";
echo "Original message: $message\n";

// ChaCha20 example
echo "\nChaCha20 Encryption:\n";
$keyChaCha = $crypto->generateKey();
$nonceChaCha = $crypto->generateIv();
$encryptedChaCha = $crypto->chaCha20Encrypt($message, $keyChaCha, $nonceChaCha);
$decryptedChaCha = $crypto->chaCha20Decrypt($encryptedChaCha['ciphertext'], $keyChaCha, $nonceChaCha);

echo "Encrypted (hex): " . bin2hex($encryptedChaCha['ciphertext']) . "\n";
echo "Decrypted: $decryptedChaCha\n";

// AES-GCM example
echo "\nAES-GCM Encryption:\n";
$keyAes = $crypto->generateKey();
$nonceAes = $crypto->generateIv();
$encryptedAes = $crypto->aesGcmEncrypt($message, $keyAes, $nonceAes);
$decryptedAes = $crypto->aesGcmDecrypt($encryptedAes['ciphertext'], $keyAes, $nonceAes, $encryptedAes['tag']);

echo "Encrypted (hex): " . bin2hex($encryptedAes['ciphertext']) . "\n";
echo "Authentication tag: " . bin2hex($encryptedAes['tag']) . "\n";
echo "Decrypted: $decryptedAes\n";

// Run comprehensive performance tests
// Using smaller sizes for demonstration
$dataSizes = [
    1024,      // 1 KB
    1024*1024, // 1 MB
    2*1024*1024 // 2 MB
];

$results = $crypto->performanceTest($dataSizes);

// Print security comparison
$crypto->printSecurityComparison(); 