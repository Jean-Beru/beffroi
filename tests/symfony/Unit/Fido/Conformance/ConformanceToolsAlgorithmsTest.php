<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Fido\Conformance;

use function array_map;
use App\Fido\Conformance\ConformanceToolsAlgorithms;
use Beffroi\Core\Bridge\Webauthn\ProviderPasskeyAlgorithms;
use function iterator_to_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\PublicKeyCredentialParameters;

final class ConformanceToolsAlgorithmsTest extends TestCase
{
    /**
     * Decision 0033
     */
    #[Test]
    public function theOptionsOfTheToolsOfferTheAlgorithmsOfTheProviderThenTheirOwn(): void
    {
        // Given
        $algorithms = new ConformanceToolsAlgorithms(new ProviderPasskeyAlgorithms());

        // When
        $parameters = $algorithms->parameters();

        // Then
        static::assertSame(
            [-8, -7, -257, -35, -65535, -36, -258, -259, -37, -38, -39],
            array_map(static fn (PublicKeyCredentialParameters $parameter): int => $parameter->alg, $parameters),
        );
    }

    /**
     * Decision 0033
     */
    #[Test]
    public function theSignaturesAreVerifiedWithEveryAlgorithmTheToolsAreOffered(): void
    {
        // Given
        $algorithms = new ConformanceToolsAlgorithms(new ProviderPasskeyAlgorithms());

        // When
        $verified = iterator_to_array($algorithms->verifiers()->list(), false);

        // Then
        static::assertSame([-8, -7, -257, -35, -65535, -36, -258, -259, -37, -38, -39], $verified);
    }

    /**
     * Decision 0033
     */
    #[Test]
    public function anAttestationFormatIsRunAsTheLibraryGivesIt(): void
    {
        // Given
        $algorithms = new ConformanceToolsAlgorithms(new ProviderPasskeyAlgorithms());
        $format = NoneAttestationStatementSupport::create();

        // When
        $support = $algorithms->attestation($format);

        // Then
        static::assertSame($format, $support);
    }
}
