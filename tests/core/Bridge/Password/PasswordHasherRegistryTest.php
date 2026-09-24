<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Password;

use function hash_equals;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\PasswordHasherRegistry;
use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Bridge\Password\Algorithm\Argon2i;
use Heidi\Core\Bridge\Password\Algorithm\Bcrypt;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Heidi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Heidi\Core\Bridge\Password\WiredPasswordAlgorithms;
use Heidi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\AlgorithmPasswordHasherInterface;
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

    /**
     * An imported hash is re-hashed with the default algorithm after its first successful verification,
     * whatever its own hasher thinks of its parameters.
     */
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

    /**
     * The wiring of the suite: argon2id first, so it is what a new hash is made with.
     */
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

/**
 * Stands for an import hasher: "verifies" by comparing the plain password with the digest prefix.
 */
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
