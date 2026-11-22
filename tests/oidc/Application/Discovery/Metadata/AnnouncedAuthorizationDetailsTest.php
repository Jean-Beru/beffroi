<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedAuthorizationDetails;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\InventedAuthorizationDetailType;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9396 §10
 */
final class AnnouncedAuthorizationDetailsTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheTypesTheWiringGaveTheProvider(): void
    {
        // Given
        $announced = new AnnouncedAuthorizationDetails(AuthorizationDetailTypes::served([
            new InventedAuthorizationDetailType(),
            new InventedAuthorizationDetailType('payment_initiation'),
        ]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [AuthorizationDetailTypes::INVENTED, 'payment_initiation'],
            $members['authorization_details_types_supported'],
        );
    }

    /**
     * RFC 9396 §10
     */
    #[Test]
    public function itAnnouncesNothingWhenNoTypeIsWired(): void
    {
        // Given
        $announced = new AnnouncedAuthorizationDetails(AuthorizationDetailTypes::none());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame([], $members);
    }
}
