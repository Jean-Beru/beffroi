<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4
 */
final class CredentialRevocationTest extends TestCase
{
    private InMemoryCredentialRepository $credentials;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private CredentialRevocation $revocation;

    protected function setUp(): void
    {
        $this->credentials = new InMemoryCredentialRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->revocation = new CredentialRevocation($this->credentials, $this->clock, $this->events);
    }

    #[Test]
    public function aRevokedPasskeyStaysListedAndIsAnnounced(): void
    {
        // Given
        $alice = Fixtures::user();
        $passkey = Fixtures::passkey($alice);
        $this->credentials->save($passkey);
        $context = Fixtures::context($this->clock->now());

        // When
        $this->revocation->revoke($passkey, $context);

        // Then
        static::assertEquals($this->clock->now(), $passkey->revokedAt);
        static::assertSame([$passkey], $this->credentials->findByUser($alice, PasskeyCredential::class));
        $events = $this->events->of(CredentialRevoked::class);
        static::assertCount(1, $events);
        static::assertSame($passkey, $events[0]->credential);
        static::assertSame($context, $events[0]->context);
    }

    #[Test]
    public function aSecondRevocationAnnouncesNothing(): void
    {
        // Given
        $passkey = Fixtures::passkey();
        $first = Fixtures::now();
        $passkey->revoke($first);
        $this->credentials->save($passkey);

        // When
        $this->revocation->revoke($passkey, Fixtures::context());

        // Then
        static::assertSame($first, $passkey->revokedAt);
        static::assertSame([], $this->events->events);
    }
}
