<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasswordChangeRefusal;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.1: a person replaces their own password, from a session they already hold, by typing
 * the one in use first.
 */
final class PasswordChangeTest extends TestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasswordHasher $hasher;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasswordChange $change;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new FakePasswordHasher();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T13:00:00+00:00');
        $this->change = new PasswordChange($this->credentials, $this->hasher, $this->clock, $this->events);
    }

    #[Test]
    public function thePasswordPosedIsTheOneHeldAfterwards(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, new PlainPassword(self::POSED), Fixtures::context());

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::POSED));
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    /**
     * The journal of a person is read to recognise what they did, and replacing their password is one of
     * the things they did.
     */
    #[Test]
    public function changingThePasswordAnnouncesTheAct(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        $this->change->change($this->alice, self::IN_USE, new PlainPassword(self::POSED), Fixtures::context());

        // Then
        $announced = $this->events->of(PasswordChanged::class);
        static::assertCount(1, $announced);
        static::assertSame($credential, $announced[0]->credential);
    }

    /**
     * A session somebody else took over does not get to replace the password it signed in with.
     */
    #[Test]
    public function aPasswordInUseThatWasNotTypedIsRefused(): void
    {
        // Given
        $this->passwordInUse();

        // Then
        $this->expectException(PasswordChangeRefusedException::class);
        $this->expectExceptionMessageIs('What was typed is not the password in use.');

        // When
        $this->change->change($this->alice, 'not the password', new PlainPassword(self::POSED), Fixtures::context());
    }

    #[Test]
    public function aPasswordThatWasNotReplacedLeavesTheOneHeldAndSaysNothing(): void
    {
        // Given
        $credential = $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, 'not the password', new PlainPassword(self::POSED), Fixtures::context());
        } catch (PasswordChangeRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify($credential->hash, self::IN_USE));
        static::assertSame([], $this->events->events);
    }

    /**
     * The page reads which refusal it was, every one of them being the same answer otherwise: the
     * password did not change.
     */
    #[Test]
    public function thePasswordPosedBeingTheOneHeldIsRefusedAsSuch(): void
    {
        // Given
        $this->passwordInUse();

        // When
        try {
            $this->change->change($this->alice, self::IN_USE, new PlainPassword(self::IN_USE), Fixtures::context());
            static::fail('The same password should have been refused.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::SameAsBefore, $exception->refusal);
        }
    }

    /**
     * Somebody who signs in by another means holds no password, and there is nothing to replace.
     */
    #[Test]
    public function aPersonWhoHoldsNoPasswordIsRefusedAsSuch(): void
    {
        // When
        try {
            $this->change->change($this->alice, self::IN_USE, new PlainPassword(self::POSED), Fixtures::context());
            static::fail('A person holding no password should have been refused.');
        } catch (PasswordChangeRefusedException $exception) {
            // Then
            static::assertSame(PasswordChangeRefusal::NoPasswordHeld, $exception->refusal);
        }
    }

    private function passwordInUse(): PasswordCredential
    {
        $credential = new PasswordCredential(Uuid::v7(), $this->alice, $this->hasher->hash(self::IN_USE), Fixtures::now());
        $this->credentials->save($credential);

        return $credential;
    }
}
