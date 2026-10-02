<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function hash;
use function hash_equals;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Port\PasswordHasherInterface;
use SensitiveParameter;

/**
 * A hasher that costs nothing and records every verification, so that tests can assert which hash a
 * secret was compared to. Never leaves the test suite.
 */
final class FakePasswordHasher implements PasswordHasherInterface
{
    /**
     * @var list<string> the encoded hashes verified against, in order
     */
    public private(set) array $verifiedAgainst = [];

    /**
     * How many times hash() was called, for tests that must see a costly hash computed once.
     */
    public private(set) int $hashed = 0;

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        ++$this->hashed;

        return new PasswordHash(new Argon2id(), 'fake:' . hash('sha256', $plainPassword));
    }

    public function verify(PasswordHash $hash, #[SensitiveParameter] string $plainPassword): bool
    {
        $this->verifiedAgainst[] = $hash->encoded;

        return hash_equals($hash->encoded, $this->hash($plainPassword)->encoded);
    }

    public function needsRehash(PasswordHash $hash): bool
    {
        return false;
    }
}
