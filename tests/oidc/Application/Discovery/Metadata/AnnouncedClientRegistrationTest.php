<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientRegistration;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\RegistrationPolicies;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3, RFC 7591 §3.1, Decision 0009
 */
final class AnnouncedClientRegistrationTest extends TestCase
{
    #[Test]
    public function aTenantWhosePolicyRegistersClientsAnnouncesWhereTheyRegister(): void
    {
        // Given
        $announced = new AnnouncedClientRegistration(new Endpoints(), RegistrationPolicies::controlled());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'registration_endpoint' => 'https://id.acme.example/register',
            ],
            $members,
        );
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aClosedTenantAnnouncesNothing(): void
    {
        // Given
        $announced = new AnnouncedClientRegistration(new Endpoints(), RegistrationPolicies::closed());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame([], $members);
    }
}
