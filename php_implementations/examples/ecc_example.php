<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Cryptography\ECC\ECCCrypto;

echo "📘 Welcome to the ECC Encryption Demo with Jeorge and Andrei!\n";

// Initialize the crypto system
$crypto = new ECCCrypto(__DIR__ . "/ecc_demo");

try {
    // Generate key pairs for both users
    [$jeorgePrivate, $jeorgePublic] = $crypto->generateEccKeyPair("jeorge");
    [$andreiPrivate, $andreiPublic] = $crypto->generateEccKeyPair("andrei");

    // Get message from user
    echo "\n💬 Jeorge, enter your secret message to Andrei: ";
    $message = trim(fgets(STDIN));

    // Jeorge encrypts message for Andrei
    [$encryptedMessage, $ephemeralPublic] = $crypto->encryptMessage($message, $andreiPublic, "jeorge");

    // Display encrypted message in base64
    echo "\n📤 Encrypted message (base64 format):\n";
    echo base64_encode(file_get_contents($encryptedMessage)) . "\n";

    // Andrei decrypts the message
    $decrypted = $crypto->decryptMessage($encryptedMessage, $ephemeralPublic, $andreiPrivate);
    echo "\n📥 Andrei decrypted the message:\n\"{$decrypted}\"\n";

    // Demonstrate ECDH key exchange
    echo "\n🔁 Demonstrating ECDH Key Exchange:\n";
    $jeorgeSecret = $crypto->performECDH($jeorgePrivate, $andreiPublic, "jeorge");
    $andreiSecret = $crypto->performECDH($andreiPrivate, $jeorgePublic, "andrei");

    echo "\n🔑 Jeorge's Shared Secret: " . bin2hex($jeorgeSecret) . "\n";
    echo "🔑 Andrei's Shared Secret: " . bin2hex($andreiSecret) . "\n";
    echo "\n✅ Shared secrets match: " . ($jeorgeSecret === $andreiSecret ? "Yes" : "No") . "\n";

} catch (Exception $e) {
    echo "\n❌ Error: " . $e->getMessage() . "\n";
    exit(1);
} 