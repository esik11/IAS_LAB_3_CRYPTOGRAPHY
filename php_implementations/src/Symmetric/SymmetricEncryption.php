<?php

namespace Cryptography\Symmetric;

class SymmetricEncryption
{
    private const AES_KEY_LENGTH = 32; // 256 bits
    private const GCM_TAG_LENGTH = 16; // 128 bits
    private const GCM_IV_LENGTH = 12;  // 96 bits
    private const CHACHA_NONCE_LENGTH = 12; // IETF version uses 96-bit nonce

    /**
     * Encrypts data using AES-256-GCM
     *
     * @param string $plaintext The data to encrypt
     * @param string $key The encryption key (32 bytes)
     * @param string $iv The initialization vector (12 bytes)
     * @return array Array containing ciphertext and authentication tag
     */
    public function aesGcmEncrypt(string $plaintext, string $key, string $iv): array
    {
        if (strlen($key) !== self::AES_KEY_LENGTH) {
            throw new \InvalidArgumentException('Key must be exactly 32 bytes long');
        }

        if (strlen($iv) !== self::GCM_IV_LENGTH) {
            throw new \InvalidArgumentException('IV must be exactly 12 bytes long');
        }

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::GCM_TAG_LENGTH
        );

        return [
            'ciphertext' => $ciphertext,
            'tag' => $tag
        ];
    }

    /**
     * Decrypts data using AES-256-GCM
     *
     * @param string $ciphertext The encrypted data
     * @param string $key The encryption key (32 bytes)
     * @param string $iv The initialization vector (12 bytes)
     * @param string $tag The authentication tag
     * @return string|false The decrypted data or false on failure
     */
    public function aesGcmDecrypt(string $ciphertext, string $key, string $iv, string $tag): string|false
    {
        if (strlen($key) !== self::AES_KEY_LENGTH) {
            throw new \InvalidArgumentException('Key must be exactly 32 bytes long');
        }

        if (strlen($iv) !== self::GCM_IV_LENGTH) {
            throw new \InvalidArgumentException('IV must be exactly 12 bytes long');
        }

        return openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
    }

    /**
     * Encrypts data using ChaCha20-Poly1305
     *
     * @param string $plaintext The data to encrypt
     * @param string $key The encryption key (32 bytes)
     * @param string $nonce The nonce (12 bytes)
     * @return array Array containing ciphertext and MAC
     */
    public function chaCha20Encrypt(string $plaintext, string $key, string $nonce): array
    {
        if (!function_exists('sodium_crypto_aead_chacha20poly1305_ietf_encrypt')) {
            throw new \RuntimeException('Sodium extension required for ChaCha20-Poly1305');
        }

        if (strlen($nonce) !== self::CHACHA_NONCE_LENGTH) {
            throw new \InvalidArgumentException('Nonce must be exactly 12 bytes long for ChaCha20-Poly1305 IETF');
        }

        $ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            '', // additional data
            $nonce,
            $key
        );

        return [
            'ciphertext' => $ciphertext,
            'nonce' => $nonce
        ];
    }

    /**
     * Decrypts data using ChaCha20-Poly1305
     *
     * @param string $ciphertext The encrypted data
     * @param string $key The encryption key (32 bytes)
     * @param string $nonce The nonce used for encryption (12 bytes)
     * @return string|false The decrypted data or false on failure
     */
    public function chaCha20Decrypt(string $ciphertext, string $key, string $nonce): string|false
    {
        if (!function_exists('sodium_crypto_aead_chacha20poly1305_ietf_decrypt')) {
            throw new \RuntimeException('Sodium extension required for ChaCha20-Poly1305');
        }

        if (strlen($nonce) !== self::CHACHA_NONCE_LENGTH) {
            throw new \InvalidArgumentException('Nonce must be exactly 12 bytes long for ChaCha20-Poly1305 IETF');
        }

        return sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            '', // additional data
            $nonce,
            $key
        );
    }

    /**
     * Generates a random encryption key
     *
     * @return string A 32-byte random key
     */
    public function generateKey(): string
    {
        return random_bytes(self::AES_KEY_LENGTH);
    }

    /**
     * Generates a random IV/nonce
     *
     * @return string A 12-byte random IV/nonce
     */
    public function generateIv(): string
    {
        return random_bytes(self::GCM_IV_LENGTH);
    }

    /**
     * Measure current resource usage
     *
     * @return array Array containing CPU and memory usage
     */
    public function measureResourceUsage(): array
    {
        if (function_exists('sys_getloadavg')) {
            $cpu = sys_getloadavg()[0];
        } else {
            $cpu = 0;
        }

        $memory = memory_get_usage(true) / 1024 / 1024; // Convert to MB
        return ['cpu' => $cpu, 'memory' => $memory];
    }

    /**
     * Run performance tests with various data sizes
     *
     * @param array|null $dataSizes Array of data sizes to test (in bytes)
     * @return array Test results
     */
    public function performanceTest(?array $dataSizes = null): array
    {
        if ($dataSizes === null) {
            $dataSizes = [
                1024*1024,      // 1MB
                10*1024*1024,   // 10MB
                100*1024*1024   // 100MB
            ];
        }

        echo "\nComprehensive Performance and Resource Usage Test\n";
        echo str_repeat("=", 60) . "\n";
        echo "System Information:\n";
        
        // Get CPU information
        $cpuInfo = "Unknown";
        if (PHP_OS === 'WINNT') {
            $wmi = new \COM('WinMgmts://');
            $cpu = $wmi->ExecQuery('SELECT * FROM Win32_Processor');
            foreach ($cpu as $processor) {
                $cpuInfo = $processor->Name;
                break;
            }
        } elseif (is_readable('/proc/cpuinfo')) {
            $cpuinfo = file_get_contents('/proc/cpuinfo');
            preg_match('/model name\s+: (.+)/', $cpuinfo, $matches);
            if (isset($matches[1])) {
                $cpuInfo = $matches[1];
            }
        }
        
        echo "CPU: {$cpuInfo}\n";
        echo "OS: " . PHP_OS . " " . php_uname('r') . "\n";
        echo str_repeat("=", 60) . "\n";

        $results = [];

        foreach ($dataSizes as $size) {
            $sizeMB = $size/1024/1024;
            echo "\nTesting with {$sizeMB}MB of data\n";
            echo str_repeat("-", 50) . "\n";

            // Generate test data
            $testData = random_bytes($size);

            // Test ChaCha20
            $keyChaCha = $this->generateKey();
            $nonceChaCha = $this->generateIv();
            
            $startUsage = $this->measureResourceUsage();
            $startTime = microtime(true);
            
            $encryptedChaCha = $this->chaCha20Encrypt($testData, $keyChaCha, $nonceChaCha);
            $decryptedChaCha = $this->chaCha20Decrypt($encryptedChaCha['ciphertext'], $keyChaCha, $nonceChaCha);
            
            $chaChaTime = microtime(true) - $startTime;
            $endUsage = $this->measureResourceUsage();
            
            $chaChaCpu = $endUsage['cpu'] - $startUsage['cpu'];
            $chaChaMem = $endUsage['memory'] - $startUsage['memory'];

            // Test AES-GCM
            $keyAes = $this->generateKey();
            $nonceAes = $this->generateIv();
            
            $startUsage = $this->measureResourceUsage();
            $startTime = microtime(true);
            
            $encryptedAes = $this->aesGcmEncrypt($testData, $keyAes, $nonceAes);
            $decryptedAes = $this->aesGcmDecrypt($encryptedAes['ciphertext'], $keyAes, $nonceAes, $encryptedAes['tag']);
            
            $aesTime = microtime(true) - $startTime;
            $endUsage = $this->measureResourceUsage();
            
            $aesCpu = $endUsage['cpu'] - $startUsage['cpu'];
            $aesMem = $endUsage['memory'] - $startUsage['memory'];

            $results[] = [
                'size' => $size,
                'chacha20' => [
                    'time' => $chaChaTime,
                    'throughput' => $size/$chaChaTime/1024/1024,
                    'cpu' => $chaChaCpu,
                    'memory' => $chaChaMem
                ],
                'aes_gcm' => [
                    'time' => $aesTime,
                    'throughput' => $size/$aesTime/1024/1024,
                    'cpu' => $aesCpu,
                    'memory' => $aesMem
                ]
            ];

            // Print results for current size
            echo "\nResults for {$sizeMB}MB:\n";
            echo "ChaCha20:\n";
            echo "  Time: " . number_format($chaChaTime, 3) . " seconds\n";
            echo "  Throughput: " . number_format($size/$chaChaTime/1024/1024, 2) . " MB/s\n";
            echo "  CPU Usage: " . number_format($chaChaCpu, 1) . "%\n";
            echo "  Memory Usage: " . number_format($chaChaMem, 1) . " MB\n";

            echo "\nAES-GCM:\n";
            echo "  Time: " . number_format($aesTime, 3) . " seconds\n";
            echo "  Throughput: " . number_format($size/$aesTime/1024/1024, 2) . " MB/s\n";
            echo "  CPU Usage: " . number_format($aesCpu, 1) . "%\n";
            echo "  Memory Usage: " . number_format($aesMem, 1) . " MB\n";

            // Verify correctness
            echo "\nVerification:\n";
            echo "ChaCha20 encryption/decryption successful: " . ($testData === $decryptedChaCha ? "True" : "False") . "\n";
            echo "AES-GCM encryption/decryption successful: " . ($testData === $decryptedAes ? "True" : "False") . "\n";
        }

        return $results;
    }

    /**
     * Print security comparison between ChaCha20 and AES-GCM
     */
    public function printSecurityComparison(): void
    {
        echo "\nSecurity Comparison\n";
        echo str_repeat("=", 60) . "\n";

        echo "\nChaCha20 Security Features:\n";
        echo "- Stream cipher with 256-bit key security\n";
        echo "- Designed for software implementation, reducing risk of side-channel attacks\n";
        echo "- No padding required, eliminating padding oracle attacks\n";
        echo "- Constant-time operations, resistant to timing attacks\n";
        echo "- No known practical attacks against the full round version\n";
        echo "- Does not provide built-in authentication (should be used with Poly1305)\n";

        echo "\nAES-GCM Security Features:\n";
        echo "- Block cipher with authenticated encryption (AEAD)\n";
        echo "- Provides both confidentiality and authenticity\n";
        echo "- Authentication tag prevents tampering\n";
        echo "- Widely analyzed and standardized\n";
        echo "- Hardware acceleration support (AES-NI)\n";
        echo "- Sensitive to nonce reuse - must ensure unique nonces\n";

        echo "\nUse Case Recommendations:\n";
        echo str_repeat("-", 60) . "\n";
        echo "Choose ChaCha20 when:\n";
        echo "- Running on systems without AES hardware acceleration\n";
        echo "- Implementing on resource-constrained devices\n";
        echo "- Need guaranteed constant-time operations\n";
        echo "- Working with software-only implementations\n";

        echo "\nChoose AES-GCM when:\n";
        echo "- Running on systems with AES-NI support\n";
        echo "- Need built-in authentication\n";
        echo "- Requiring FIPS compliance\n";
        echo "- Working with hardware acceleration\n";
    }
} 