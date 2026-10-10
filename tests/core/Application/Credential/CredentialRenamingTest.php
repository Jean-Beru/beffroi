<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\CredentialRenaming;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Event\CredentialRenamed;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.1: what tells one credential of a person from another is a name they wrote, so naming it
 * again is their own act.
 */
final class CredentialRenamingTest extends TestCase
{
    private InMemoryCredentialRepository $credentials;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private CredentialRenaming $renaming;

    protected function setUp(): void
    {
        $this->credentials = new InMemoryCredentialRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-10-10T12:00:00+00:00');
        $this->renaming = new CredentialRenaming($this->credentials, $this->clock, $this->events);
    }

    #[Test]
    public function aRenamedPasskeyKeepsTheNameItWasGivenAndTheActIsAnnounced(): void
    {
        // Given
        $alice = Fixtures::user();
        $passkey = Fixtures::passkey($alice);
        $this->credentials->save($passkey);
        $was = $passkey->name;
        $context = Fixtures::context($this->clock->now());

        // When
        $this->renaming->rename($passkey, 'The key of my telephone', $context);

        // Then
        static::assertSame('The key of my telephone', $passkey->name);
        $events = $this->events->of(CredentialRenamed::class);
        static::assertCount(1, $events);
        static::assertSame($was, $events[0]->was);
        static::assertSame($passkey, $events[0]->credential);
        static::assertSame($context, $events[0]->context);
    }

    /**
     * The name it already holds is not a change, and the journal of a person does not hold a line saying
     * they changed nothing.
     */
    #[Test]
    public function theNameItAlreadyHoldsAnnouncesNothing(): void
    {
        // Given
        $alice = Fixtures::user();
        $passkey = Fixtures::passkey($alice);
        $this->credentials->save($passkey);

        // When
        $this->renaming->rename($passkey, $passkey->name, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([], $this->events->of(CredentialRenamed::class));
    }

    /**
     * A name is read on the server under the rule of the kind, whatever a page let somebody type.
     */
    #[Test]
    public function aNameThePasskeyCannotHoldIsRefused(): void
    {
        // Given
        $passkey = Fixtures::passkey(Fixtures::user());
        $this->credentials->save($passkey);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A passkey name is 1 to');

        // When
        $this->renaming->rename($passkey, '   ', Fixtures::context($this->clock->now()));
    }
}
