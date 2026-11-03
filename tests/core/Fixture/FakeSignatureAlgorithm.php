<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm as JoseAlgorithm;

/**
 * An algorithm no line of the core, the module or the provider knows about: what a deployment adds when a
 * profile asks for one more. It signs over P-256 like ES256, under a name of its own.
 */
final readonly class FakeSignatureAlgorithm implements JoseSignatureAlgorithmInterface
{
    /**
     * @param non-empty-string $name
     */
    public function __construct(
        private string $name = 'ES256UNWIRED',
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function keyType(): string
    {
        return 'EC';
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function digestAlgorithm(): string
    {
        return 'sha256';
    }

    public function joseAlgorithm(): JoseAlgorithm
    {
        return new RenamedEs256($this->name);
    }

    public function generateKey(): JWK
    {
        return JWKFactory::createECKey('P-256', [
            'alg' => $this->name,
            'use' => $this->keyUse()->value,
        ]);
    }
}
