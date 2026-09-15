<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Password;

use function hash_equals;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\PasswordHasherRegistry;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\PasswordHasherInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SensitiveParameter;

final class PasswordHasherRegistryTest extends TestCase
{
    #[Test]
    public function itHashesWithTheDefaultAlgorithm(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()]);

        // When
        $hash = $registry->hash('secret');

        // Then
        static::assertSame(PasswordAlgorithm::Argon2id, $hash->algorithm);
        static::assertTrue($registry->verify($hash, 'secret'));
        static::assertFalse($registry->needsRehash($hash));
    }

    #[Test]
    public function itVerifiesWithTheHasherOfTheAlgorithm(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()]);
        $imported = new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'secret-digest');

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
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()]);

        // When / Then
        static::assertTrue($registry->needsRehash(new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'secret-digest')));
    }

    #[Test]
    public function itRefusesToVerifyAnAlgorithmNoHasherHandles(): void
    {
        // Given
        $registry = new PasswordHasherRegistry([new NativePasswordHasher()]);

        // Then
        $this->expectException(LogicException::class);

        // When
        $registry->verify(new PasswordHash(PasswordAlgorithm::Pbkdf2Sha512, 'digest'), 'secret');
    }

    #[Test]
    public function itNeedsAHasherForTheDefaultAlgorithm(): void
    {
        // Then
        $this->expectException(LogicException::class);

        // When
        new PasswordHasherRegistry([new FakePbkdf2Hasher()]);
    }

    #[Test]
    public function itNeedsAtLeastOneHasher(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new PasswordHasherRegistry([]);
    }
}

/**
 * Stands for an import hasher: "verifies" by comparing the plain password with the digest prefix.
 */
final class FakePbkdf2Hasher implements PasswordHasherInterface
{
    public function supports(PasswordAlgorithm $algorithm): bool
    {
        return $algorithm === PasswordAlgorithm::Pbkdf2Sha256;
    }

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        return new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, $plainPassword . '-digest');
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
