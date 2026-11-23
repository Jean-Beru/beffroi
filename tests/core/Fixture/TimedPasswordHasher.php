<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function hash;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Port\PasswordHasherInterface;
use SensitiveParameter;

/**
 * Hashes as FakePasswordHasher does, and moves a clock by what a verification costs under the algorithm of the hash;
 * it would replace any hash that is not argon2id.
 */
final readonly class TimedPasswordHasher implements PasswordHasherInterface
{
    /**
     * @param array<string, int> $costs nanoseconds a verification takes, by name of algorithm
     */
    public function __construct(
        private FakeMonotonicClock $clock,
        private array $costs,
        private FakePasswordHasher $hasher = new FakePasswordHasher(),
    ) {
    }

    public static function hashOf(PasswordAlgorithmInterface $algorithm, #[SensitiveParameter] string $password): PasswordHash
    {
        return new PasswordHash($algorithm, 'fake:' . hash('sha256', $password));
    }

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        return $this->hasher->hash($plainPassword);
    }

    public function verify(PasswordHash $hash, #[SensitiveParameter] string $plainPassword): bool
    {
        $this->clock->advance($this->costs[$hash->algorithm->name()] ?? 0);

        return $this->hasher->verify($hash, $plainPassword);
    }

    public function needsRehash(PasswordHash $hash): bool
    {
        return $hash->algorithm->name() !== Argon2id::NAME;
    }
}
