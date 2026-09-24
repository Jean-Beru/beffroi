<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Password;

use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Bridge\Password\Algorithm\Bcrypt;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use const PASSWORD_ARGON2_DEFAULT_MEMORY_COST;
use const PASSWORD_BCRYPT;
use function password_hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
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
    public function itAsksForARehashWhenTheParametersGrew(): void
    {
        // Given
        $weaker = new NativePasswordHasher();
        $stronger = new NativePasswordHasher(memoryCost: PASSWORD_ARGON2_DEFAULT_MEMORY_COST * 2);
        $hash = $weaker->hash('secret');

        // When / Then
        static::assertTrue($stronger->needsRehash($hash));
    }

    #[Test]
    public function itStillVerifiesAHashOfWeakerParameters(): void
    {
        // Given
        $weaker = new NativePasswordHasher();
        $stronger = new NativePasswordHasher(memoryCost: PASSWORD_ARGON2_DEFAULT_MEMORY_COST * 2);
        $hash = $weaker->hash('secret');

        // When / Then
        static::assertTrue($stronger->verify($hash, 'secret'));
    }

    #[Test]
    public function itRefusesParametersBelowTheDefaultsOfPhp(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new NativePasswordHasher(timeCost: 1);
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
