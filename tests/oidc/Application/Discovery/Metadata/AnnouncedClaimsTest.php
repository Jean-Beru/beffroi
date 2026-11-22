<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\FakeClaimsProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3, OIDC Core §5.5
 */
final class AnnouncedClaimsTest extends TestCase
{
    #[Test]
    public function theyAreSubAndWhatTheClaimsProviderSupplies(): void
    {
        // Given
        $announced = new AnnouncedClaims(new StandardClaimsProvider());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['sub', ...new StandardClaimsProvider()->supportedClaims()], $members['claims_supported']);
        static::assertTrue($members['claims_parameter_supported']);
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function subComesFirstAndOnce(): void
    {
        // Given
        $announced = new AnnouncedClaims(FakeClaimsProvider::of([], ['email', 'sub', 'email']));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['sub', 'email'], $members['claims_supported']);
    }

    #[Test]
    public function subIsAnnouncedEvenWhenTheIntegrationListsNothing(): void
    {
        // Given
        $announced = new AnnouncedClaims(FakeClaimsProvider::of([], []));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['sub'], $members['claims_supported']);
    }

    #[Test]
    public function anEmptyClaimNameIsRefused(): void
    {
        // Given
        $announced = new AnnouncedClaims(FakeClaimsProvider::of([], ['']));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A supported claim has a name.');

        // When
        $announced->metadata(Fixtures::tenant());
    }
}
