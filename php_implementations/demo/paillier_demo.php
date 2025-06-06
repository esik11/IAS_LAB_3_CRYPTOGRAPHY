<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Cryptography\Homomorphic\Paillier;

// Generate a public and private key pair for encryption and decryption
$paillier = Paillier::generateKeyPair(2048); // Explicitly set key size to match Python

// Define the log file path
$log_file = __DIR__ . "/../../paillier_log.txt";

/**
 * Function to write encryption operations and results to a log file
 */
function log_to_file($operation, $a, $b, $encrypted_a, $encrypted_b, $encrypted_result, $decrypted_result) {
    global $log_file;
    
    // Get microsecond precision timestamp
    $date = new DateTime();
    $timestamp = $date->format('Y-m-d H:i:s.u');
    
    $log_entry = "===== New Operation =====\n";
    $log_entry .= "Timestamp: {$timestamp}\n";
    $log_entry .= "Operation: {$operation}\n";
    $log_entry .= "Input A: {$a}\n";
    $log_entry .= "Input B: {$b}\n";
    $log_entry .= "Encrypted A: " . $encrypted_a->ciphertext() . "\n";
    $log_entry .= "Encrypted B: " . ($encrypted_b ? $encrypted_b->ciphertext() : "N/A") . "\n";
    $log_entry .= "Encrypted Result: " . $encrypted_result->ciphertext() . "\n";
    $log_entry .= "Decrypted Result: {$decrypted_result}\n";
    $log_entry .= "=========================\n\n";
    
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

/**
 * Main user interface loop
 */
function main_menu() {
    global $paillier;
    
    echo "🔐 Paillier Homomorphic Encryption with Logging\n";
    
    while (true) {
        echo "\nChoose an operation:\n";
        echo "1. Encrypted Addition (A + B)\n";
        echo "2. Encrypted Multiplication (A × plain B)\n";
        echo "3. Exit\n\n";
        
        echo "Enter your choice: ";
        $choice = trim(fgets(STDIN));
        
        // Homomorphic Addition: encrypted_a + encrypted_b = encryption of (a + b)
        if ($choice === '1') {
            try {
                echo "Enter number A: ";
                $a = (int)trim(fgets(STDIN));
                
                echo "Enter number B: ";
                $b = (int)trim(fgets(STDIN));
                
                // Encrypt both inputs
                $encrypted_a = $paillier->encrypt($a);
                $encrypted_b = $paillier->encrypt($b);
                
                // ✅ Homomorphic operation: computation on encrypted data
                $encrypted_result = $encrypted_a->__add($encrypted_b);
                
                // Decrypt the result for verification
                $decrypted_result = $paillier->decrypt($encrypted_result);
                
                // Show result to user
                echo "\nDecrypted Result: {$a} + {$b} = {$decrypted_result}\n";
                
                // Log all details
                log_to_file("Addition", $a, $b, $encrypted_a, $encrypted_b, $encrypted_result, $decrypted_result);
                
            } catch (Exception $e) {
                echo "❌ Please enter valid integers.\n";
            }
        }
        
        // Homomorphic Scalar Multiplication: encrypted_a * b = encryption of (a * b)
        elseif ($choice === '2') {
            try {
                echo "Enter number A (to encrypt): ";
                $a = (int)trim(fgets(STDIN));
                
                echo "Enter constant B (plaintext): ";
                $b = (int)trim(fgets(STDIN));
                
                // Encrypt the first input
                $encrypted_a = $paillier->encrypt($a);
                
                // ✅ Homomorphic operation: scalar multiplication on encrypted data
                $encrypted_result = $encrypted_a->__mul($b);
                
                // Decrypt the result for verification
                $decrypted_result = $paillier->decrypt($encrypted_result);
                
                // Show result to user
                echo "\nDecrypted Result: {$a} * {$b} = {$decrypted_result}\n";
                
                // Log operation; encrypted_b is null here since B is plaintext
                log_to_file("Multiplication", $a, $b, $encrypted_a, null, $encrypted_result, $decrypted_result);
                
            } catch (Exception $e) {
                echo "❌ Please enter valid integers.\n";
            }
        }
        
        // Exit the program
        elseif ($choice === '3') {
            echo "📁 Log saved in: " . realpath($GLOBALS['log_file']) . "\n";
            echo "👋 Exiting.\n";
            break;
        }
        
        else {
            echo "❗ Invalid choice. Choose 1, 2, or 3.\n";
        }
    }
}

// Run the menu function to start the program
main_menu(); 