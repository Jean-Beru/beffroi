<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use SensitiveParameter;
use Symfony\Component\KeyManagement\Ciphertext;
use Symfony\Component\KeyManagement\DataKey;
use Symfony\Component\KeyManagement\DataKeyGeneratorInterface;
use Symfony\Component\KeyManagement\DecrypterInterface;
use Symfony\Component\KeyManagement\EncrypterInterface;

final class CountingKms implements DataKeyGeneratorInterface, DecrypterInterface, EncrypterInterface
{
    public int $minted = 0;

    public int $unwrapped = 0;

    public function __construct(
        private readonly DataKeyGeneratorInterface&DecrypterInterface&EncrypterInterface $kms,
    ) {
    }

    public function forget(): void
    {
        $this->minted = 0;
        $this->unwrapped = 0;
    }

    public function generateDataKey(string $keyId, int $length = 32, string $aad = ''): DataKey
    {
        ++$this->minted;

        return $this->kms->generateDataKey($keyId, $length, $aad);
    }

    public function wrapDataKey(string $keyId, #[SensitiveParameter] string $dataKey, string $aad = ''): Ciphertext
    {
        return $this->kms->wrapDataKey($keyId, $dataKey, $aad);
    }

    public function unwrapDataKey(Ciphertext $wrapped, string $aad = ''): DataKey
    {
        ++$this->unwrapped;

        return $this->kms->unwrapDataKey($wrapped, $aad);
    }

    public function encrypt(string $keyId, #[SensitiveParameter] string $plaintext, string $aad = ''): Ciphertext
    {
        return $this->kms->encrypt($keyId, $plaintext, $aad);
    }

    public function decrypt(Ciphertext $ciphertext, string $aad = ''): string
    {
        return $this->kms->decrypt($ciphertext, $aad);
    }
}
