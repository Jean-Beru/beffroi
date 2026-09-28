<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\FakeClaimsProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: "claims_supported" is "sub" and what the claims provider may supply, and a client
 * may ask for them by name (OIDC Core §5.5).
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
     * OIDC Core §2: "sub" is always a claim; it comes first whatever the integration lists, and a claim
     * listed twice is announced once.
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
