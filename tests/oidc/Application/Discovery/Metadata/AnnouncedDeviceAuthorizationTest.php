<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedDeviceAuthorization;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8628 §4: the one member the specification registers, which is where a client with no browser starts.
 * The grant that goes with it is announced by the fact of being wired, as every other grant is.
 */
final class AnnouncedDeviceAuthorizationTest extends TestCase
{
    #[Test]
    public function itNamesTheEndpointOfTheTenant(): void
    {
        // Given
        $announced = new AnnouncedDeviceAuthorization(new Endpoints(), Grants::servedWithDeviceCode());

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'device_authorization_endpoint' => 'https://as.example/acme/device_authorization',
            ],
            $members,
        );
    }

    /**
     * A contributor announces nothing rather than an endpoint nothing serves: a provider wired with no
     * grant whose user is asked on another device would refuse every client there (issue #839).
     */
    #[Test]
    public function aProviderWiredWithNoSuchGrantAnnouncesNothing(): void
    {
        // Given
        $announced = new AnnouncedDeviceAuthorization(new Endpoints(), Grants::served());

        // When / Then
        static::assertSame([], $announced->metadata(Fixtures::tenant()));
    }
}
