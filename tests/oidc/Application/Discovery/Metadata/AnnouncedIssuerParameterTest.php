<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9207 §3, Decision 0006
 */
final class AnnouncedIssuerParameterTest extends TestCase
{
    #[Test]
    public function itSaysEveryAuthorizationResponseNamesTheIssuer(): void
    {
        // When
        $members = new AnnouncedIssuerParameter()->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'authorization_response_iss_parameter_supported' => true,
            ],
            $members,
        );
    }
}
