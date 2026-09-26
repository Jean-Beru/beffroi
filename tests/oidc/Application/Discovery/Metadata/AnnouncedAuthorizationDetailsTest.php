<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedAuthorizationDetails;
use Heidi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Heidi\Oidc\Tests\Fixture\InventedAuthorizationDetailType;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9396 §10 "authorization_details_types_supported": which types of authorization detail a client may
 * name in an "authorization_details" parameter (§2). What is announced is what the wiring gave the
 * provider, read from it and not from a list kept beside it.
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
     * A member a client would read as "no type is acceptable here" is not written at all, §10 making it
     * optional for exactly the provider that serves no rich authorization request.
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
