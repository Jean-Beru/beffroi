<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use SensitiveParameter;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeDecrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypterInterface;
use Throwable;

final readonly class EnvelopesThatThrow implements EnvelopeEncrypterInterface, EnvelopeDecrypterInterface
{
    public function __construct(
        private Throwable $exception,
    ) {
    }

    public function encrypt(string $key, #[SensitiveParameter] string $plaintext, string $aad = ''): Envelope
    {
        throw $this->exception;
    }

    public function decrypt(Envelope $envelope, string $aad = ''): string
    {
        throw $this->exception;
    }
}
