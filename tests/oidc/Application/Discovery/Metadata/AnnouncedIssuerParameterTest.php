<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9207 §3 and decision 0006: the provider names itself in every authorization response, so it says
 * so; oidc_login compares this member to true with ===.
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
