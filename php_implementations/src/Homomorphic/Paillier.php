<?php

namespace Cryptography\Homomorphic;

use phpseclib3\Math\BigInteger;

class Paillier
{
    private BigInteger $n;  // n = p * q
    private BigInteger $g;  // g = n + 1
    private BigInteger $lambda;  // lambda = lcm(p-1, q-1)
    private BigInteger $mu;  // mu = (L(g^lambda mod n^2))^(-1) mod n
    private BigInteger $n2;  // n^2

    /**
     * Generate a new key pair for Paillier encryption
     * 
     * @param int $bits Key size in bits (default 2048)
     * @return array Array containing public and private key components
     */
    public static function generateKeyPair(int $bits = 2048): self
    {
        $instance = new self();
        
        // Generate two large prime numbers
        $p = BigInteger::randomPrime($bits / 2);
        $q = BigInteger::randomPrime($bits / 2);
        
        // Calculate n = p * q
        $instance->n = $p->multiply($q);
        
        // Calculate lambda = lcm(p-1, q-1)
        $p1 = $p->subtract(new BigInteger(1));
        $q1 = $q->subtract(new BigInteger(1));
        $instance->lambda = $instance->lcm($p1, $q1);
        
        // g = n + 1
        $instance->g = $instance->n->add(new BigInteger(1));
        
        // n^2
        $instance->n2 = $instance->n->multiply($instance->n);
        
        // Calculate mu = (L(g^lambda mod n^2))^(-1) mod n
        $l = $instance->L($instance->g->powMod($instance->lambda, $instance->n2), $instance->n);
        $instance->mu = $l->modInverse($instance->n);
        
        return $instance;
    }

    /**
     * Encrypt a number using the public key
     * 
     * @param int|string $m The number to encrypt
     * @return EncryptedNumber
     */
    public function encrypt($m): EncryptedNumber
    {
        $m = new BigInteger($m);
        
        // Generate random r
        $r = BigInteger::randomRange(new BigInteger(1), $this->n);
        
        // c = (g^m * r^n) mod n^2
        $gm = $this->g->powMod($m, $this->n2);
        $rn = $r->powMod($this->n, $this->n2);
        $c = $gm->multiply($rn)->divide($this->n2)[1]; // mod operation using divide remainder
        
        return new EncryptedNumber($c, $this);
    }

    /**
     * Decrypt a number using the private key
     * 
     * @param EncryptedNumber $encrypted_number The encrypted number
     * @return string The decrypted number as a string
     */
    public function decrypt(EncryptedNumber $encrypted_number): string
    {
        $c = $encrypted_number->getCiphertext();
        
        // m = L(c^lambda mod n^2) * mu mod n
        $x = $c->powMod($this->lambda, $this->n2);
        $L = $this->L($x, $this->n);
        $m = $L->multiply($this->mu)->divide($this->n)[1]; // mod operation using divide remainder
        
        return $m->toString();
    }

    /**
     * Helper function L(x, n) = (x-1)/n
     */
    private function L(BigInteger $x, BigInteger $n): BigInteger
    {
        return $x->subtract(new BigInteger(1))->divide($n)[0];
    }

    /**
     * Calculate Least Common Multiple
     */
    private function lcm(BigInteger $a, BigInteger $b): BigInteger
    {
        $gcd = $a->gcd($b);
        return $a->multiply($b)->divide($gcd)[0];
    }

    /**
     * Get the public key n value
     */
    public function getN(): BigInteger
    {
        return $this->n;
    }

    /**
     * Get n^2 value
     */
    public function getN2(): BigInteger
    {
        return $this->n2;
    }
}

/**
 * Class to represent an encrypted number in the Paillier cryptosystem
 */
class EncryptedNumber
{
    private BigInteger $ciphertext;
    private Paillier $paillier;

    public function __construct(BigInteger $ciphertext, Paillier $paillier)
    {
        $this->ciphertext = $ciphertext;
        $this->paillier = $paillier;
    }

    /**
     * Add another encrypted number
     */
    public function __add(EncryptedNumber $other): EncryptedNumber
    {
        $sum = $this->ciphertext->multiply($other->ciphertext)->divide($this->paillier->getN2())[1]; // mod operation
        return new EncryptedNumber($sum, $this->paillier);
    }

    /**
     * Multiply by a plain number (scalar multiplication)
     */
    public function __mul($scalar): EncryptedNumber
    {
        $scalar = new BigInteger($scalar);
        $result = $this->ciphertext->powMod($scalar, $this->paillier->getN2());
        return new EncryptedNumber($result, $this->paillier);
    }

    /**
     * Get the ciphertext value
     */
    public function getCiphertext(): BigInteger
    {
        return $this->ciphertext;
    }

    /**
     * Get ciphertext as string for logging
     */
    public function ciphertext(): string
    {
        return $this->ciphertext->toString();
    }
} 