<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use function array_map;
use Beffroi\Core\Bridge\Webauthn\ProviderPasskeyAlgorithms;
use Beffroi\Core\Bridge\Webauthn\Rs1RefusingAttestationStatementSupport;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\PublicKeyCredentialParameters;

final class ProviderPasskeyAlgorithmsTest extends TestCase
{
    /**
     * Decision 0033: EdDSA over Ed25519, ES256 and RS256, from the strongest to the weakest
     * (w3c/webauthn#2448), ES384 not among them.
     */
    #[Test]
    public function theOptionsOfferTheAlgorithmsOfTheProviderFromTheStrongest(): void
    {
        // Given
        $algorithms = new ProviderPasskeyAlgorithms();

        // When
        $parameters = $algorithms->parameters();

        // Then
        static::assertSame(
            [-8, -7, -257],
            array_map(static fn (PublicKeyCredentialParameters $parameter): int => $parameter->alg, $parameters),
        );
    }

    /**
     * Decision 0033: the signatures are verified with the algorithms the options offer, and none other,
     * neither ES384 (-35) nor RS1 (-65535) among them.
     */
    #[Test]
    public function theSignaturesAreVerifiedWithTheOfferedAlgorithmsAlone(): void
    {
        // Given
        $algorithms = new ProviderPasskeyAlgorithms();

        // When
        $verified = iterator_to_array($algorithms->verifiers()->list(), false);

        // Then
        static::assertSame([-8, -7, -257], $verified);
    }

    /**
     * Decision 0033: what the product verifies of an attestation statement goes through the refusal of RS1.
     */
    #[Test]
    public function anAttestationFormatIsRunRefusingRs1(): void
    {
        // Given
        $algorithms = new ProviderPasskeyAlgorithms();

        // When
        $support = $algorithms->attestation(NoneAttestationStatementSupport::create());

        // Then
        static::assertInstanceOf(Rs1RefusingAttestationStatementSupport::class, $support);
    }
}
