<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function hash;
use function hash_equals;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Port\PasswordHasherInterface;
use SensitiveParameter;

final class FakePasswordHasher implements PasswordHasherInterface
{
    /**
     * @var list<string>
     */
    public private(set) array $verifiedAgainst = [];

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
