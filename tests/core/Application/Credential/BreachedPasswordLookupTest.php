<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\BreachedPasswordLookup;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Exception\BreachLookupFailedException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class BreachedPasswordLookupTest extends TestCase
{
    private const string A_PASSWORD = 'correct horse battery staple';

    private const string BREACHED = 'monkey business as usual';

    private InMemoryCredentialRepository $credentials;

    private MockClock $clock;

    private PasswordCredential $credential;

    protected function setUp(): void
    {
        $this->credentials = new InMemoryCredentialRepository();
        $this->clock = new MockClock('2026-10-10T12:00:00+00:00');
        $this->credential = new PasswordCredential(
            Uuid::v7(),
            Fixtures::user(),
            new FakePasswordHasher()->hash(self::A_PASSWORD),
            Fixtures::now(),
        );
        $this->credentials->save($this->credential);
    }

    #[Test]
    public function aPasswordTheListCountsIsMarkedAsFound(): void
    {
        // When
        $this->lookup(BreachedPasswordsOfARecord::holding([self::BREACHED]))->lookUp($this->credential, PasswordDigest::of(self::BREACHED));

        // Then
        static::assertTrue($this->credential->isBreached());
        static::assertEquals($this->clock->now(), $this->credential->breachFoundAt);
        static::assertEquals($this->clock->now(), $this->credential->breachCheckedAt);
    }

    #[Test]
    public function aPasswordTheListDoesNotHoldIsMarkedAsLookedUpAndNotFound(): void
    {
        // When
        $this->lookup(BreachedPasswordsOfARecord::holding([self::BREACHED]))->lookUp($this->credential, PasswordDigest::of(self::A_PASSWORD));

        // Then
        static::assertFalse($this->credential->isBreached());
        static::assertEquals($this->clock->now(), $this->credential->breachCheckedAt);
    }

    #[Test]
    public function theDigestItWasHandedIsWhatTheListIsAskedAbout(): void
    {
        // Given
        $breaches = BreachedPasswordsOfARecord::holding([self::BREACHED]);

        // When
        $this->lookup($breaches)->lookUp($this->credential, PasswordDigest::of(self::A_PASSWORD));

        // Then
        static::assertSame([PasswordDigest::of(self::A_PASSWORD)->value], $breaches->asked);
    }

    #[Test]
    public function aDeploymentThatNamesNoListMarksNothing(): void
    {
        // When
        $this->lookup(new BreachedPasswordsOfARecord(looksUp: false))->lookUp($this->credential, PasswordDigest::of(self::A_PASSWORD));

        // Then
        static::assertNull($this->credential->breachCheckedAt);
        static::assertTrue($this->credential->dueForABreachLookup($this->clock->now()));
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aListThatCouldNotBeAskedLeavesTheCredentialAlone(): void
    {
        // Given
        $lookup = $this->lookup(new BreachedPasswordsOfARecord(unreachable: true));

        // When
        try {
            $lookup->lookUp($this->credential, PasswordDigest::of(self::A_PASSWORD));
            static::fail('A list that could not be asked throws.');
        } catch (BreachLookupFailedException) {
            // Then
            static::assertNull($this->credential->breachCheckedAt);
            static::assertFalse($this->credential->isBreached());
        }
    }

    private function lookup(BreachedPasswordsOfARecord $breaches): BreachedPasswordLookup
    {
        return new BreachedPasswordLookup($breaches, $this->credentials, $this->clock);
    }
}
