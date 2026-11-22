<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Dpop;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Dpop\DpopChallengeParameters;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §7.1
 */
final class DpopChallengeParametersTest extends TestCase
{
    /**
     * RFC 9449 §7.1
     */
    #[Test]
    public function theDpopChallengeNamesTheAlgorithmsAProofMaySignWith(): void
    {
        // Given
        $parameters = new DpopChallengeParameters(new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()));

        // When
        $challengeParameters = $parameters->challengeParameters();

        // Then
        static::assertSame(
            [
                'DPoP' => [
                    'algs' => 'RS256 PS256 ES256 EdDSA',
                ],
            ],
            $challengeParameters,
        );
    }
}
