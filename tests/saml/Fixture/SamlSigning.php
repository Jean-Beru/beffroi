<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;

final readonly class SamlSigning implements SamlSigningAlgorithmInterface
{
    public function name(): string
    {
        return 'SAML-SIGNING';
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }
}
