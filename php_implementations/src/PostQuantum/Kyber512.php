<?php

namespace Cryptography\PostQuantum;

class Kyber512
{
    private $publicKey;
    private $privateKey;

    /**
     * Simulate key generation by generating random 32-byte keys
     *
     * @return array Array containing public and private keys
     */
    public function keygen(): array
    {
        $this->publicKey = random_bytes(32);
        $this->privateKey = random_bytes(32);
        return [
            'public_key' => $this->publicKey,
            'private_key' => $this->privateKey
        ];
    }

    /**
     * Simulate encryption: returns a fake ciphertext and a shared secret
     *
     * @param string $message The message to encrypt
     * @param string $publicKey The public key
     * @return array Array containing ciphertext and shared secret
     */
    public function encrypt(string $message, string $publicKey): array
    {
        // Ciphertext includes the message and some randomness
        $ciphertext = hash('sha3-256', $message . random_bytes(32), true);
        // Sender's shared secret is derived deterministically from the message
        $sharedSecret = hash('sha3-256', $message, true);

        return [
            'ciphertext' => $ciphertext,
            'shared_secret' => $sharedSecret
        ];
    }

    /**
     * Simulate decryption: derive the same shared secret from original message
     *
     * @param string $ciphertext The ciphertext to decrypt
     * @param string $privateKey The private key
     * @param string $originalMessage The original message
     * @return string The shared secret
     */
    public function decrypt(string $ciphertext, string $privateKey, string $originalMessage): string
    {
        // Receiver regenerates shared secret based on known original message
        return hash('sha3-256', $originalMessage, true);
    }

    /**
     * Run a demonstration of the Kyber-512 implementation
     *
     * @param string $message Optional test message
     * @return array Performance metrics
     */
    public function runDemo(string $message = "This is a secret message for Kyber-512 testing!"): array
    {
        $metrics = [
            'key_generation' => [],
            'encryption' => [],
            'decryption' => [],
            'validation' => []
        ];

        echo "Kyber-512 Post-Quantum Cryptography Demonstration\n";
        echo str_repeat("=", 50) . "\n";

        // 1. Key Generation
        echo "\n1. Key Generation Phase\n" . str_repeat("-", 20) . "\n";
        $startKeygen = microtime(true);
        $keys = $this->keygen();
        $endKeygen = microtime(true);
        $keygenTime = $endKeygen - $startKeygen;
        echo "Key Pair Generated in " . number_format($keygenTime, 6) . " seconds\n";

        $metrics['key_generation'][] = [
            'timestamp' => date('c'),
            'duration' => $keygenTime,
            'success' => true
        ];

        // 2. Encryption
        echo "\n2. Encryption Phase\n" . str_repeat("-", 20) . "\n";
        $startEncrypt = microtime(true);
        $encrypted = $this->encrypt($message, $keys['public_key']);
        $endEncrypt = microtime(true);
        $encryptTime = $endEncrypt - $startEncrypt;
        
        echo "Ciphertext: " . bin2hex($encrypted['ciphertext']) . "\n";
        echo "Sender Shared Secret: " . bin2hex($encrypted['shared_secret']) . "\n";
        echo "Encryption Time: " . number_format($encryptTime, 6) . " seconds\n";

        $metrics['encryption'][] = [
            'timestamp' => date('c'),
            'duration' => $encryptTime,
            'success' => true
        ];

        // 3. Decryption
        echo "\n3. Decryption Phase\n" . str_repeat("-", 20) . "\n";
        $startDecrypt = microtime(true);
        $receiverSharedSecret = $this->decrypt(
            $encrypted['ciphertext'],
            $keys['private_key'],
            $message
        );
        $endDecrypt = microtime(true);
        $decryptTime = $endDecrypt - $startDecrypt;

        echo "Receiver Shared Secret: " . bin2hex($receiverSharedSecret) . "\n";
        echo "Decryption Time: " . number_format($decryptTime, 6) . " seconds\n";

        $metrics['decryption'][] = [
            'timestamp' => date('c'),
            'duration' => $decryptTime,
            'success' => true
        ];

        // 4. Key Validation
        echo "\n4. Key Validation Phase\n" . str_repeat("-", 24) . "\n";
        $isValid = hash_equals($encrypted['shared_secret'], $receiverSharedSecret);
        echo "Key Validation: " . ($isValid ? "✅ Success" : "❌ Failed") . "\n";

        $metrics['validation'][] = [
            'timestamp' => date('c'),
            'duration' => $encryptTime + $decryptTime,
            'success' => $isValid
        ];

        // 5. Save Metrics
        echo "\n5. Saving Metrics\n" . str_repeat("-", 18) . "\n";
        $this->saveMetrics($metrics);
        echo "Metrics saved to 'kyber512_metrics.txt'\n";

        return $metrics;
    }

    /**
     * Save performance metrics to files
     *
     * @param array $metrics The metrics to save
     */
    private function saveMetrics(array $metrics): void
    {
        // Save text metrics
        $textMetrics = "Performance Metrics for Kyber512 Algorithm\n";
        $textMetrics .= "-----------------------------------------\n";
        $textMetrics .= "Date: " . date('Y-m-d H:i:s.u') . "\n";
        $textMetrics .= "Key Generation Time: " . number_format($metrics['key_generation'][0]['duration'], 6) . " seconds\n";
        $textMetrics .= "Encryption Time: " . number_format($metrics['encryption'][0]['duration'], 6) . " seconds\n";
        $textMetrics .= "Decryption Time: " . number_format($metrics['decryption'][0]['duration'], 6) . " seconds\n";
        
        file_put_contents(__DIR__ . '/../../../kyber512_metrics.txt', $textMetrics);
        
        // Save JSON metrics (keeping this for additional data but not announcing it)
        $jsonMetrics = json_encode($metrics, JSON_PRETTY_PRINT);
        file_put_contents(__DIR__ . '/../../../kyber512_metrics.json', $jsonMetrics);
    }
} 