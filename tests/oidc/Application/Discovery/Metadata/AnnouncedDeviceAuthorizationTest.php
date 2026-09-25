<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedDeviceAuthorization;
use Heidi\Oidc\Tests\Fixture\Endpoints;
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
        $announced = new AnnouncedDeviceAuthorization(new Endpoints());

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
}
