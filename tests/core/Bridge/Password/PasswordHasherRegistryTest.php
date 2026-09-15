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
    public function itHashesWithTheDefaultAndVerifiesWithTheHasherOfTheAlgorithm(): void
    {
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()]);

        $fresh = $registry->hash('secret');
        static::assertSame(PasswordAlgorithm::Argon2id, $fresh->algorithm);
        static::assertTrue($registry->verify($fresh, 'secret'));
        static::assertFalse($registry->needsRehash($fresh));

        $imported = new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'secret-digest');
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
        $registry = new PasswordHasherRegistry([new NativePasswordHasher(), new FakePbkdf2Hasher()]);

        static::assertTrue($registry->needsRehash(new PasswordHash(PasswordAlgorithm::Pbkdf2Sha256, 'secret-digest')));
    }

    #[Test]
    public function itRefusesToVerifyAnAlgorithmNoHasherHandles(): void
    {
        $registry = new PasswordHasherRegistry([new NativePasswordHasher()]);

        $this->expectException(LogicException::class);
        $registry->verify(new PasswordHash(PasswordAlgorithm::Pbkdf2Sha512, 'digest'), 'secret');
    }

    #[Test]
    public function itNeedsAHasherForTheDefaultAlgorithm(): void
    {
        $this->expectException(LogicException::class);

        new PasswordHasherRegistry([new FakePbkdf2Hasher()]);
    }

    #[Test]
    public function itNeedsAtLeastOneHasher(): void
    {
        $this->expectException(InvalidArgumentException::class);

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
