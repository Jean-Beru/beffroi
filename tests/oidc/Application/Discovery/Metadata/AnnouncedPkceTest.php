<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7636 §4.2, Decision 0006
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
     * RFC 8414 §2
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
