from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
import time
import os
import psutil
import platform

def generate_key_nonce(key_size):
    """Generate random key and nonce."""
    key = get_random_bytes(key_size)
    nonce = get_random_bytes(12)  # 96-bit nonce for both ChaCha20 and AES-GCM
    return key, nonce

def chacha20_encrypt(data, key, nonce):
    """Encrypt data using ChaCha20."""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)

def chacha20_decrypt(ciphertext, key, nonce):
    """Decrypt data using ChaCha20."""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

def aes_gcm_encrypt(data, key, nonce):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def aes_gcm_decrypt(ciphertext, key, nonce, tag):
    """Decrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def measure_resource_usage():
    """Measure current CPU and memory usage."""
    cpu_percent = psutil.cpu_percent()
    memory = psutil.Process().memory_info().rss / 1024 / 1024  # Convert to MB
    return cpu_percent, memory

def performance_test(data_sizes=None):
    """Test performance of both encryption methods with various data sizes."""
    if data_sizes is None:
        data_sizes = [1024*1024, 10*1024*1024, 100*1024*1024]  # 1MB, 10MB, 100MB
    
    print("\nComprehensive Performance and Resource Usage Test")
    print("=" * 60)
    print(f"System Information:")
    print(f"CPU: {platform.processor()}")
    print(f"OS: {platform.system()} {platform.version()}")
    print("=" * 60)
    
    results = []
    
    for size in data_sizes:
        print(f"\nTesting with {size/1024/1024:.1f}MB of data")
        print("-" * 50)
        
        # Generate test data
        test_data = os.urandom(size)
        
        # Test ChaCha20
        key_chacha, nonce_chacha = generate_key_nonce(32)
        start_cpu, start_mem = measure_resource_usage()
        start_time = time.time()
        encrypted_chacha = chacha20_encrypt(test_data, key_chacha, nonce_chacha)
        decrypted_chacha = chacha20_decrypt(encrypted_chacha, key_chacha, nonce_chacha)
        chacha_time = time.time() - start_time
        end_cpu, end_mem = measure_resource_usage()
        chacha_cpu = end_cpu - start_cpu
        chacha_mem = end_mem - start_mem
        
        # Test AES-GCM
        key_aes, nonce_aes = generate_key_nonce(32)
        start_cpu, start_mem = measure_resource_usage()
        start_time = time.time()
        encrypted_aes, tag = aes_gcm_encrypt(test_data, key_aes, nonce_aes)
        decrypted_aes = aes_gcm_decrypt(encrypted_aes, key_aes, nonce_aes, tag)
        aes_time = time.time() - start_time
        end_cpu, end_mem = measure_resource_usage()
        aes_cpu = end_cpu - start_cpu
        aes_mem = end_mem - start_mem
        
        results.append({
            'size': size,
            'chacha20': {
                'time': chacha_time,
                'throughput': size/chacha_time/1024/1024,
                'cpu': chacha_cpu,
                'memory': chacha_mem
            },
            'aes_gcm': {
                'time': aes_time,
                'throughput': size/aes_time/1024/1024,
                'cpu': aes_cpu,
                'memory': aes_mem
            }
        })
        
        # Print results for current size
        print(f"\nResults for {size/1024/1024:.1f}MB:")
        print(f"ChaCha20:")
        print(f"  Time: {chacha_time:.3f} seconds")
        print(f"  Throughput: {size/chacha_time/1024/1024:.2f} MB/s")
        print(f"  CPU Usage: {chacha_cpu:.1f}%")
        print(f"  Memory Usage: {chacha_mem:.1f} MB")
        
        print(f"\nAES-GCM:")
        print(f"  Time: {aes_time:.3f} seconds")
        print(f"  Throughput: {size/aes_time/1024/1024:.2f} MB/s")
        print(f"  CPU Usage: {aes_cpu:.1f}%")
        print(f"  Memory Usage: {aes_mem:.1f} MB")
        
        # Verify correctness
        print("\nVerification:")
        print(f"ChaCha20 encryption/decryption successful: {test_data == decrypted_chacha}")
        print(f"AES-GCM encryption/decryption successful: {test_data == decrypted_aes}")
    
    return results

def print_security_comparison():
    """Print a detailed security comparison between ChaCha20 and AES-GCM."""
    print("\nSecurity Comparison")
    print("=" * 60)
    
    print("\nChaCha20 Security Features:")
    print("- Stream cipher with 256-bit key security")
    print("- Designed for software implementation, reducing risk of side-channel attacks")
    print("- No padding required, eliminating padding oracle attacks")
    print("- Constant-time operations, resistant to timing attacks")
    print("- No known practical attacks against the full round version")
    print("- Does not provide built-in authentication (should be used with Poly1305)")
    
    print("\nAES-GCM Security Features:")
    print("- Block cipher with authenticated encryption (AEAD)")
    print("- Provides both confidentiality and authenticity")
    print("- Authentication tag prevents tampering")
    print("- Widely analyzed and standardized")
    print("- Hardware acceleration support (AES-NI)")
    print("- Sensitive to nonce reuse - must ensure unique nonces")
    
    print("\nUse Case Recommendations:")
    print("-" * 60)
    print("Choose ChaCha20 when:")
    print("- Running on systems without AES hardware acceleration")
    print("- Implementing on resource-constrained devices")
    print("- Need guaranteed constant-time operations")
    print("- Working with software-only implementations")
    
    print("\nChoose AES-GCM when:")
    print("- Running on systems with AES-NI support")
    print("- Need built-in authentication")
    print("- Requiring FIPS compliance")
    print("- Working with hardware acceleration")

def main():
    # Basic encryption example
    message = b"Hello, this is a secret message!"
    print("Original message:", message.decode())
    
    # ChaCha20 example
    print("\nChaCha20 Encryption:")
    key_chacha, nonce_chacha = generate_key_nonce(32)
    encrypted_chacha = chacha20_encrypt(message, key_chacha, nonce_chacha)
    decrypted_chacha = chacha20_decrypt(encrypted_chacha, key_chacha, nonce_chacha)
    print("Encrypted (hex):", encrypted_chacha.hex())
    print("Decrypted:", decrypted_chacha.decode())
    
    # AES-GCM example
    print("\nAES-GCM Encryption:")
    key_aes, nonce_aes = generate_key_nonce(32)
    encrypted_aes, tag = aes_gcm_encrypt(message, key_aes, nonce_aes)
    decrypted_aes = aes_gcm_decrypt(encrypted_aes, key_aes, nonce_aes, tag)
    print("Encrypted (hex):", encrypted_aes.hex())
    print("Authentication tag:", tag.hex())
    print("Decrypted:", decrypted_aes.decode())
    
    # Run comprehensive performance tests
    results = performance_test()
    
    # Print security comparison
    print_security_comparison()

if __name__ == "__main__":
    main() 