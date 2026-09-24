<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Security;

use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\AlgorithmPasswordHasherInterface;
use const PASSWORD_ARGON2ID;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use SensitiveParameter;
use function sprintf;

/**
 * The argon2id hasher of the test kernel: genuine argon2id hashes, "$argon2id$" strings that the native
 * hasher of the core verifies as well, at the smallest cost the algorithm accepts, a millisecond and a
 * mebibyte instead of the 400 ms and 64 MiB of the defaults of PHP the native hasher refuses to go below
 * (RFC 9106 §4). Tagged ahead of the native hasher, it takes every argon2id hash of the suite: the
 * passwords of the users, the ten backup codes of a TOTP, the secrets of the clients rehashed at every
 * reboot of the kernel, the decoys. The native hasher keeps the hashes of the other algorithms, so that
 * a bcrypt hash is still verified and rehashed on login. Never leaves the test suite.
 */
final readonly class CheapArgon2idHasher implements AlgorithmPasswordHasherInterface
{
    /**
     * @var array{memory_cost: int, time_cost: int, threads: int}
     */
    private const array OPTIONS = [
        'memory_cost' => 1024,
        'time_cost' => 1,
        'threads' => 1,
    ];

    public function supports(PasswordAlgorithmInterface $algorithm): bool
    {
        return $algorithm->name() === Argon2id::NAME;
    }

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        return new PasswordHash(new Argon2id(), password_hash($plainPassword, PASSWORD_ARGON2ID, self::OPTIONS));
    }

    public function verify(PasswordHash $hash, #[SensitiveParameter] string $plainPassword): bool
    {
        $this->assertSupported($hash->algorithm);

        return password_verify($plainPassword, $hash->encoded);
    }

    public function needsRehash(PasswordHash $hash): bool
    {
        $this->assertSupported($hash->algorithm);

        return password_needs_rehash($hash->encoded, PASSWORD_ARGON2ID, self::OPTIONS);
    }

    private function assertSupported(PasswordAlgorithmInterface $algorithm): void
    {
        if (! $this->supports($algorithm)) {
            throw new LogicException(sprintf('The cheap hasher handles argon2id hashes only, not "%s"; route them through the registry.', $algorithm->name()));
        }
    }
}
