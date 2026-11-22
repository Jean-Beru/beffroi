<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Password;

use function hash_equals;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\PasswordHasherRegistry;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2i;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Port\AlgorithmPasswordHasherInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SensitiveParameter;

final class PasswordHasherRegistryTest extends TestCase
{
    #[Test]
    public function itHashesWithTheDefaultAlgorithm(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()], self::algorithms());

        // When
        $hash = $registry->hash('secret');

        // Then
        static::assertSame(Argon2id::NAME, $hash->algorithm->name());
        static::assertTrue($registry->verify($hash, 'secret'));
        static::assertFalse($registry->needsRehash($hash));
    }

    #[Test]
    public function itVerifiesWithTheHasherOfTheAlgorithm(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()], self::algorithms());
        $imported = new PasswordHash(new Pbkdf2Sha256(), 'secret-digest');

        // When / Then
        static::assertTrue($registry->verify($imported, 'secret'));
        static::assertFalse($registry->verify($imported, 'other'));
    }

    #[Test]
    public function aHashOfAnotherAlgorithmThanTheDefaultAlwaysNeedsARehash(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()], self::algorithms());

        // When / Then
        static::assertTrue($registry->needsRehash(new PasswordHash(new Pbkdf2Sha256(), 'secret-digest')));
    }

    #[Test]
    public function itRefusesToVerifyAnAlgorithmNoHasherHandles(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher()], self::algorithms());

        // Then
        $this->expectException(LogicException::class);

        // When
        $registry->verify(new PasswordHash(new Pbkdf2Sha512(), 'digest'), 'secret');
    }

    #[Test]
    public function itNeedsAHasherForTheDefaultAlgorithm(): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        new PasswordHasherRegistry([new FakePbkdf2Hasher()], self::algorithms());
    }

    private static function algorithms(): WiredPasswordAlgorithms
    {
        return new WiredPasswordAlgorithms([new Argon2id(), new Argon2i(), new Bcrypt(), new Pbkdf2Sha256()]);
    }

    #[Test]
    public function itNeedsAtLeastOneHasher(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new PasswordHasherRegistry([], self::algorithms());
    }
}

final class FakePbkdf2Hasher implements AlgorithmPasswordHasherInterface
{
    public function supports(PasswordAlgorithmInterface $algorithm): bool
    {
        return $algorithm->name() === Pbkdf2Sha256::NAME;
    }

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        return new PasswordHash(new Pbkdf2Sha256(), $plainPassword . '-digest');
    }

    public function verify(PasswordHash $hash, #[SensitiveParameter] string $plainPassword): bool
    {
        return hash_equals($hash->encoded, $plainPassword . '-digest');
    }

    public function needsRehash(PasswordHash $hash): bool
    {
        return false;
    }
}
