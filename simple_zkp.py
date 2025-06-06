import random
import hashlib

class SimpleZKP:
    def __init__(self):
        # A large prime number
        self.p = 2**255 - 19  # Curve25519 prime
        # A generator number
        self.g = 2
        
    def generate_secret(self):
        """Generate a random secret"""
        return random.randint(1, self.p-1)
    
    def calculate_public(self, secret):
        """Calculate public value: g^secret mod p"""
        return pow(self.g, secret, self.p)
    
    def generate_challenge(self):
        """Generate a random challenge"""
        return random.randint(1, self.p-1)
    
    def create_proof(self, secret, challenge):
        """Create proof: response = secret * challenge mod (p-1)"""
        return (secret * challenge) % (self.p - 1)
    
    def verify_proof(self, public, challenge, proof):
        """Verify the proof"""
        left_side = pow(self.g, proof, self.p)
        right_side = pow(public, challenge, self.p)
        return left_side == right_side

def demo_zkp():
    # Create ZKP instance
    zkp = SimpleZKP()
    
    # Prover's secret
    secret = zkp.generate_secret()
    print(f"Prover's secret: {secret}")
    
    # Calculate public value
    public = zkp.calculate_public(secret)
    print(f"Public value: {public}")
    
    # Verifier generates challenge
    challenge = zkp.generate_challenge()
    print(f"Challenge: {challenge}")
    
    # Prover creates proof
    proof = zkp.create_proof(secret, challenge)
    print(f"Proof: {proof}")
    
    # Verifier checks proof
    is_valid = zkp.verify_proof(public, challenge, proof)
    print(f"Proof is valid: {is_valid}")

if __name__ == "__main__":
    demo_zkp() 