<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Authentication;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\TimedPasswordHasher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DecoyHashTest extends TestCase
{
    private const int DECOY = 117_800_000;

    private const int CHEAPER = 87_700_000;

    private const int COSTLIER = 350_800_000;

    private FakePasswordHasher $hasher;

    private DecoyHash $decoy;

    private FakeMonotonicClock $time;

    protected function setUp(): void
    {
        $this->hasher = new FakePasswordHasher();
        $this->decoy = new DecoyHash($this->hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock());
        $this->time = new FakeMonotonicClock();
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function itPaysOneVerificationAgainstAHashOfTheHasher(): void
    {
        // When
        $this->decoy->verify('whatever');

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertStringStartsWith('fake:', $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function theDecoyIsNotTheHashOfThePassword(): void
    {
        // When
        $this->decoy->verify('whatever');

        // Then
        static::assertNotSame($this->hasher->hash('whatever')->encoded, $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function theSameDecoyServesEveryVerification(): void
    {
        // When
        $this->decoy->verify('first');
        $this->decoy->verify('second');

        // Then
        static::assertCount(2, $this->hasher->verifiedAgainst);
        static::assertSame($this->hasher->verifiedAgainst[0], $this->hasher->verifiedAgainst[1]);
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function aHashCheaperThanTheDecoyTakesTheTimeOfTheDecoy(): void
    {
        // Given
        $decoy = $this->timed(self::CHEAPER);
        $decoy->verify('whatever');
        $start = $this->time->now();

        // When
        $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), 'not the password');

        // Then
        static::assertSame(self::DECOY, $this->time->now() - $start);
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function aHashCostlierThanTheDecoyWaitsNothing(): void
    {
        // Given
        $decoy = $this->timed(self::COSTLIER);
        $decoy->verify('whatever');

        // When
        $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), 'not the password');

        // Then
        static::assertSame([], $this->time->waited);
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function aHashVerifiedBeforeTheDecoyWasMeasuredPaysTheDecoyAsWell(): void
    {
        // Given
        $decoy = $this->timed(self::CHEAPER);
        $start = $this->time->now();

        // When
        $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), 'not the password');

        // Then
        static::assertSame(self::CHEAPER + self::DECOY, $this->time->now() - $start);
        static::assertSame([], $this->time->waited);
    }

    /**
     * Decision 0058
     */
    #[Test]
    public function theTimeWaitedForIsTheLastTheDecoyTook(): void
    {
        // Given
        $decoy = $this->timed(self::CHEAPER);
        $decoy->verify('whatever');
        $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), 'not the password');

        // When
        $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), 'not the password');

        // Then
        static::assertSame([self::DECOY - self::CHEAPER, self::DECOY - self::CHEAPER], $this->time->waited);
    }

    #[Test]
    #[DataProvider('provideVerdicts')]
    public function itAnswersWhatTheHashSays(string $password, bool $verified): void
    {
        // Given
        $decoy = $this->timed(self::CHEAPER);
        $decoy->verify('whatever');

        // When / Then
        static::assertSame($verified, $decoy->verifyNoFaster(TimedPasswordHasher::hashOf(new Bcrypt(), 'carol pass'), $password));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideVerdicts(): iterable
    {
        yield 'the password of the hash' => ['carol pass', true];
        yield 'another password' => ['not the password', false];
    }

    private function timed(int $bcrypt): DecoyHash
    {
        $hasher = new TimedPasswordHasher($this->time, [Argon2id::NAME => self::DECOY, Bcrypt::NAME => $bcrypt]);

        return new DecoyHash($hasher, new SymfonyUuidGenerator(), $this->time);
    }
}
