<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Cryptography\PostQuantum\Kyber512;

// Create new instance of Kyber512
$kyber = new Kyber512();

// Run the demonstration
$metrics = $kyber->runDemo(); 