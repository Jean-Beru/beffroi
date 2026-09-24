<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7636 §4.2 and decision 0006: the provider takes "S256" and nothing else, so "plain" is never
 * announced, whatever a client asks for.
 */
final class AnnouncedPkceTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheOneMethodTheProviderTakes(): void
    {
        // When
        $members = new AnnouncedPkce()->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'code_challenge_methods_supported' => ['S256'],
            ],
            $members,
        );
    }
}
