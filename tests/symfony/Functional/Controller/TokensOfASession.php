<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\Tokens;

trait TokensOfASession
{
    /**
     * @return array{refresh: string, access: string}
     */
    private static function tokensIssuedIn(AuthenticationSession $session): array
    {
        $tokens = [
            'refresh' => Secrets::draw(),
            'access' => Secrets::draw(),
        ];
        $client = self::client();
        $issuedAt = self::currentSecond();
        self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)
            ->save(Tokens::refreshToken($tokens['refresh'], $client, $session, $issuedAt));
        self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)
            ->save(Tokens::storedAccessToken($tokens['access'], $client, $session, $issuedAt));

        return $tokens;
    }

    /**
     * RFC 6750 §3.1
     *
     * @param array{refresh: string, access: string} $tokens
     */
    private static function assertTheTokensAreRevoked(array $tokens): void
    {
        self::reload();
        $refreshToken = self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)
            ->findByTokenHash(DrawnSecret::digestOf($tokens['refresh']));
        $accessToken = self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)->find($tokens['access']);

        static::assertSame(
            [
                'the refresh token revoked' => true,
                'the access token found' => false,
            ],
            [
                'the refresh token revoked' => $refreshToken?->isRevoked(),
                'the access token found' => $accessToken !== null,
            ],
        );
    }
}
