<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function is_string;
use LogicException;
use const OPENSSL_ALGO_SHA256;
use function openssl_sign;

/**
 * WebAuthn Level 3 §8.2: the certificate an authenticator signs its attestation with, and the key of that certificate.
 */
final readonly class AttestationCertificate
{
    public function __construct(
        private string $privateKey,
        public string $der,
        public string $pem,
    ) {
    }

    /**
     * RFC 9053 §2.1, ES256
     */
    public function algorithm(): int
    {
        return -7;
    }

    public function sign(string $data): string
    {
        if (! openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new LogicException('OpenSSL could not sign.');
        }

        return $signature;
    }
}
