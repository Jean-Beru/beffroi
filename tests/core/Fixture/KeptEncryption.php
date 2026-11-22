<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeptEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;

final readonly class KeptEncryption implements KeptEncryptionAlgorithmInterface
{
    public function __construct(
        private string $holder = 'a',
        private KeyUse $use = KeyUse::Encryption,
    ) {
    }

    public function name(): string
    {
        return 'KEPT-ENCRYPTION:' . $this->holder;
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return $this->use;
    }
}
