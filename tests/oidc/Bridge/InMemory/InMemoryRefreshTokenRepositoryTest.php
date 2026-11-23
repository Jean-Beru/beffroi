<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\InMemory;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700 §4.14.2
 */
final class InMemoryRefreshTokenRepositoryTest extends TestCase
{
    private InMemoryRefreshTokenRepository $tokens;

    private RefreshToken $token;

    protected function setUp(): void
    {
        $user = Fixtures::user();
        $this->tokens = new InMemoryRefreshTokenRepository();
        $this->token = Tokens::refreshToken('the-token', Clients::public($user->tenant), Fixtures::session($user), Fixtures::now());
        $this->tokens->save($this->token);
    }

    #[Test]
    public function aTokenNeitherRotatedNorRevokedIsRotated(): void
    {
        // When
        $this->tokens->rotate($this->token, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $this->token->rotatedAt);
    }

    #[Test]
    public function aTokenIsRotatedOnce(): void
    {
        // Given
        $this->tokens->rotate($this->token, Fixtures::now());

        // When / Then
        static::assertFalse($this->tokens->rotate($this->token, Fixtures::now()));
    }

    #[Test]
    public function aRevokedTokenIsNotRotated(): void
    {
        // Given
        $this->token->revoke(Fixtures::now());

        // When / Then
        static::assertFalse($this->tokens->rotate($this->token, Fixtures::now()));
    }
}
