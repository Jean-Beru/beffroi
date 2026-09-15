<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function hash;
use function hash_equals;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Port\PasswordHasherInterface;
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

    public function supports(PasswordAlgorithm $algorithm): bool
    {
        return $algorithm === PasswordAlgorithm::Argon2id;
    }

    public function hash(#[SensitiveParameter] string $plainPassword): PasswordHash
    {
        return new PasswordHash(PasswordAlgorithm::Argon2id, 'fake:' . hash('sha256', $plainPassword));
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
