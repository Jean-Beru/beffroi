<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A store where a refresh in flight writes its successor just after the first read of the family.
 */
final class SuccessorWrittenAfterARead implements RefreshTokenRepositoryInterface
{
    private ?RefreshToken $successor;

    public function __construct(
        private readonly InMemoryRefreshTokenRepository $tokens,
        RefreshToken $successor,
    ) {
        $this->successor = $successor;
    }

    public function findByTokenHash(string $tokenHash): ?RefreshToken
    {
        return $this->tokens->findByTokenHash($tokenHash);
    }

    public function findByFamily(Uuid $family): array
    {
        $found = $this->tokens->findByFamily($family);
        if ($this->successor !== null) {
            $this->tokens->save($this->successor);
            $this->successor = null;
        }

        return $found;
    }

    public function findByAuthorizationCode(string $codeHash): array
    {
        return $this->tokens->findByAuthorizationCode($codeHash);
    }

    public function findBySession(Uuid $session): array
    {
        return $this->tokens->findBySession($session);
    }

    public function save(RefreshToken $token): void
    {
        $this->tokens->save($token);
    }
}
