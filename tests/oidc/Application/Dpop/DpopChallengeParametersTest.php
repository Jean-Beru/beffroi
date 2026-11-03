<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Dpop;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Dpop\DpopChallengeParameters;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §7.1: what a challenge under the DPoP scheme says of it whatever the refusal.
 */
final class DpopChallengeParametersTest extends TestCase
{
    /**
     * RFC 9449 §7.1: "algs" is the space-delimited list of what a proof may be signed with, which is what
     * the provider is wired to sign with, in the order it is wired.
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
