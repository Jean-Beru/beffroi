<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeptSigningAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;

final readonly class KeptSigning implements KeptSigningAlgorithmInterface
{
    public function __construct(
        private KeyUse $use = KeyUse::Signature,
    ) {
    }

    public function name(): string
    {
        return 'KEPT-SIGNING';
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
