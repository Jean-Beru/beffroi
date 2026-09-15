<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Password;

use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
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
    public function itHashesWithArgon2idAndVerifiesTheRightPasswordOnly(): void
    {
        $hasher = new NativePasswordHasher();

        $hash = $hasher->hash('correct horse battery staple');

        static::assertSame(PasswordAlgorithm::Argon2id, $hash->algorithm);
        static::assertTrue(str_starts_with($hash->encoded, '$argon2id$'));
        static::assertTrue($hasher->verify($hash, 'correct horse battery staple'));
        static::assertFalse($hasher->verify($hash, 'Correct horse battery staple'));
        static::assertFalse($hasher->needsRehash($hash));
    }

    #[Test]
    public function itVerifiesABcryptHashAndAsksForItsRehash(): void
    {
        $hasher = new NativePasswordHasher();
        $legacy = new PasswordHash(PasswordAlgorithm::Bcrypt, password_hash('secret', PASSWORD_BCRYPT));

        static::assertTrue($hasher->verify($legacy, 'secret'));
        static::assertTrue($hasher->needsRehash($legacy));
    }

    #[Test]
    public function itAsksForARehashWhenTheParametersGrew(): void
    {
        $weaker = new NativePasswordHasher();
        $stronger = new NativePasswordHasher(memoryCost: PASSWORD_ARGON2_DEFAULT_MEMORY_COST * 2);

        $hash = $weaker->hash('secret');

        static::assertFalse($weaker->needsRehash($hash));
        static::assertTrue($stronger->needsRehash($hash));
        static::assertTrue($stronger->verify($hash, 'secret'));
    }

    #[Test]
    public function itRefusesParametersBelowTheDefaultsOfPhp(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new NativePasswordHasher(timeCost: 1);
    }

    #[Test]
    public function itDoesNotPretendToVerifyAnAlgorithmItDoesNotImplement(): void
    {
        $hasher = new NativePasswordHasher();
        static::assertFalse($hasher->supports(PasswordAlgorithm::Pbkdf2Sha256));

        $this->expectException(LogicException::class);
        $hasher->verify(new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'digest'), 'secret');
    }
}
