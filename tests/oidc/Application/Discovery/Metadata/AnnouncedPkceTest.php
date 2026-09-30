<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Heidi\Oidc\Tests\Fixture\ChallengeMethods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7636 §4.2: what is announced is what the provider is wired to verify a challenge with. Decision
 * 0006 wires "S256" alone, and "plain" is a class the module does not ship, so it is announced nowhere.
 */
final class AnnouncedPkceTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheOneMethodTheProviderIsWiredWith(): void
    {
        // When
        $members = new AnnouncedPkce(ChallengeMethods::s256())->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'code_challenge_methods_supported' => ['S256'],
            ],
            $members,
        );
    }

    /**
     * RFC 8414 §2: a deployment that wires a method of its own is announced with it, and nothing here is
     * edited for that.
     */
    #[Test]
    public function itAnnouncesAMethodADeploymentWiredOfItsOwn(): void
    {
        // When
        $members = new AnnouncedPkce(ChallengeMethods::s256AndInvented())->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'code_challenge_methods_supported' => ['S256', 'S512'],
            ],
            $members,
        );
    }
}
