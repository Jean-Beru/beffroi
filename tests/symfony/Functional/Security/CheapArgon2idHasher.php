<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Port\AlgorithmPasswordHasherInterface;
use const PASSWORD_ARGON2ID;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use SensitiveParameter;
use function sprintf;

/**
 * RFC 9106 §4
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
