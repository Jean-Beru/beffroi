<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Client;

use DateTimeImmutable;
use Heidi\Bundle\Client\ClientAssertionReplayGuard;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * RFC 7523 §3 and §4: an assertion authenticates once, and the "jti" that says so is remembered until it
 * expires.
 */
final class ClientAssertionReplayGuardTest extends TestCase
{
    private ClientAssertionReplayGuard $guard;

    private DateTimeImmutable $expiresAt;

    protected function setUp(): void
    {
        $this->guard = new ClientAssertionReplayGuard(new ArrayAdapter());
        // the pool expires an item against the wall clock, so the assertion expires ahead of it
        $this->expiresAt = new DateTimeImmutable('+1 hour');
    }

    #[Test]
    public function anIdentifierNotSeenYetIsRemembered(): void
    {
        // When / Then
        static::assertTrue($this->guard->remember(Clients::withSharedSecret(Fixtures::tenant()), 'once', $this->expiresAt));
    }

    #[Test]
    public function anIdentifierAlreadySeenIsRefused(): void
    {
        // Given
        $client = Clients::withSharedSecret(Fixtures::tenant());
        $this->guard->remember($client, 'once', $this->expiresAt);

        // When / Then
        static::assertFalse($this->guard->remember($client, 'once', $this->expiresAt));
    }

    /**
     * RFC 7523 §3: a "jti" is unique to the client that issued it, and two clients may use the same one.
     */
    #[Test]
    public function twoClientsMayUseTheSameIdentifier(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $this->guard->remember(Clients::withSharedSecret($tenant, 'first'), 'once', $this->expiresAt);

        // When / Then
        static::assertTrue($this->guard->remember(Clients::withSharedSecret($tenant, 'second'), 'once', $this->expiresAt));
    }
}
