<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;

/**
 * spec/saml.md S-64
 */
final readonly class SamlEncryption implements SamlEncryptionAlgorithmInterface
{
    public function __construct(
        private string $identityProvider,
    ) {
    }

    public function name(): string
    {
        return self::NAME_PREFIX . $this->identityProvider;
    }

    public function keyType(): string
    {
        return 'RSA';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Encryption;
    }

    public function identityProvider(): string
    {
        return $this->identityProvider;
    }
}
