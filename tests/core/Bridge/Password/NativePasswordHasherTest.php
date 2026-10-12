<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Password;

use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use const PASSWORD_ARGON2ID;
use const PASSWORD_BCRYPT;
use function password_get_info;
use function password_hash;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_starts_with;

final class NativePasswordHasherTest extends TestCase
{
    #[Test]
    public function itHashesWithArgon2id(): void
    {
        // Given
        $hasher = new NativePasswordHasher();

        // When
        $hash = $hasher->hash('correct horse battery staple');

        // Then
        static::assertSame(Argon2id::NAME, $hash->algorithm->name());
        static::assertTrue(str_starts_with($hash->encoded, '$argon2id$'));
        static::assertFalse($hasher->needsRehash($hash));
    }

    /**
     * RFC 9106 §4 asks for 64 MiB of memory, three passes and four lanes in its memory-constrained set. The memory and
     * the passes are read as a floor, what PHP defaults to being that memory and a pass more; the lanes are exact.
     */
    #[Test]
    public function itHashesWithTheParameterSetOfRfc9106(): void
    {
        // Given
        $hasher = new NativePasswordHasher();

        // When
        $hash = $hasher->hash('correct horse battery staple');

        // Then
        $parameters = password_get_info($hash->encoded)['options'];
        static::assertGreaterThanOrEqual(65_536, $parameters['memory_cost']);
        static::assertGreaterThanOrEqual(3, $parameters['time_cost']);
        static::assertSame(4, $parameters['threads']);
    }

    #[Test]
    public function itVerifiesTheRightPassword(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $hash = $hasher->hash('correct horse battery staple');

        // When / Then
        static::assertTrue($hasher->verify($hash, 'correct horse battery staple'));
    }

    #[Test]
    public function itRefusesAWrongPassword(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $hash = $hasher->hash('correct horse battery staple');

        // When / Then
        static::assertFalse($hasher->verify($hash, 'Correct horse battery staple'));
    }

    #[Test]
    public function itVerifiesABcryptHash(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $legacy = new PasswordHash(new Bcrypt(), password_hash('secret', PASSWORD_BCRYPT));

        // When / Then
        static::assertTrue($hasher->verify($legacy, 'secret'));
    }

    #[Test]
    public function itAsksForTheRehashOfABcryptHash(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $legacy = new PasswordHash(new Bcrypt(), password_hash('secret', PASSWORD_BCRYPT));

        // When / Then
        static::assertTrue($hasher->needsRehash($legacy));
    }

    #[Test]
    public function itAsksForTheRehashOfAHashOfOneLane(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $oneLane = new PasswordHash(new Argon2id(), password_hash('secret', PASSWORD_ARGON2ID, [
            'memory_cost' => NativePasswordHasher::MEMORY_COST,
            'time_cost' => NativePasswordHasher::TIME_COST,
            'threads' => 1,
        ]));

        // When / Then
        static::assertTrue($hasher->needsRehash($oneLane));
    }

    #[Test]
    public function itAsksForARehashWhenTheParametersGrew(): void
    {
        // Given
        $weaker = new NativePasswordHasher();
        $stronger = new NativePasswordHasher(memoryCost: NativePasswordHasher::MEMORY_COST * 2);
        $hash = $weaker->hash('secret');

        // When / Then
        static::assertTrue($stronger->needsRehash($hash));
    }

    #[Test]
    public function itStillVerifiesAHashOfWeakerParameters(): void
    {
        // Given
        $weaker = new NativePasswordHasher();
        $stronger = new NativePasswordHasher(memoryCost: NativePasswordHasher::MEMORY_COST * 2);
        $hash = $weaker->hash('secret');

        // When / Then
        static::assertTrue($stronger->verify($hash, 'secret'));
    }

    #[Test]
    #[DataProvider('provideParametersBelowTheFloor')]
    public function itRefusesParametersBelowItsFloor(int $memoryCost, int $timeCost, int $threads): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'argon2id parameters cannot go below %d KiB of memory, %d passes and %d lanes.',
            NativePasswordHasher::MEMORY_COST,
            NativePasswordHasher::TIME_COST,
            NativePasswordHasher::THREADS,
        ));

        // When
        new NativePasswordHasher($memoryCost, $timeCost, $threads);
    }

    /**
     * @return iterable<string, array{int, int, int}>
     */
    public static function provideParametersBelowTheFloor(): iterable
    {
        yield 'less memory' => [NativePasswordHasher::MEMORY_COST - 1, NativePasswordHasher::TIME_COST, NativePasswordHasher::THREADS];
        yield 'a pass fewer' => [NativePasswordHasher::MEMORY_COST, NativePasswordHasher::TIME_COST - 1, NativePasswordHasher::THREADS];
        yield 'a lane fewer' => [NativePasswordHasher::MEMORY_COST, NativePasswordHasher::TIME_COST, NativePasswordHasher::THREADS - 1];
    }

    #[Test]
    public function itDoesNotSupportAnAlgorithmItDoesNotImplement(): void
    {
        // Given
        $hasher = new NativePasswordHasher();

        // When / Then
        static::assertFalse($hasher->supports(new Pbkdf2Sha256()));
    }

    #[Test]
    public function itDoesNotPretendToVerifyAnAlgorithmItDoesNotImplement(): void
    {
        // Given
        $hasher = new NativePasswordHasher();

        // Then
        $this->expectException(LogicException::class);

        // When
        $hasher->verify(new PasswordHash(new Pbkdf2Sha256(), 'digest'), 'secret');
    }
}
