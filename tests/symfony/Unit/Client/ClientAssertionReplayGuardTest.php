<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Client;

use DateTimeImmutable;
use App\Cache\SeenOnce;
use App\Client\ClientAssertionReplayGuard;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\InMemoryStore;

/**
 * RFC 7523 §3, §4
 */
final class ClientAssertionReplayGuardTest extends TestCase
{
    private ClientAssertionReplayGuard $guard;

    private DateTimeImmutable $expiresAt;

    protected function setUp(): void
    {
        $this->guard = new ClientAssertionReplayGuard(new SeenOnce(new ArrayAdapter(), new LockFactory(new InMemoryStore())));
        // The pool expires its items against the wall clock, so the assertion expires an hour ahead of it.
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
     * RFC 7523 §3
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
