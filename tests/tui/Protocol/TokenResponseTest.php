<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Protocol\RejectedAnswerException;
use Beffroi\Tui\Protocol\TokenResponse;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §5: the access token is bound to the key of this run, or it is not taken.
 */
final class TokenResponseTest extends TestCase
{
    #[Test]
    public function aBearerTokenIsRefused(): void
    {
        // Given
        $answer = new Document(['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 300]);

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIs('The provider answered a token of the type "Bearer", which is not bound to the key of this program (RFC 9449 §5).');

        // When
        TokenResponse::fromDocument($answer);
    }

    /**
     * RFC 6749 §5.1: the type is compared without regard to case.
     */
    #[Test]
    public function theTypeOfABoundTokenIsReadWithoutRegardToCase(): void
    {
        // When
        $tokens = TokenResponse::fromDocument(new Document(['access_token' => 'at', 'token_type' => 'dpop', 'expires_in' => 300, 'refresh_token' => 'rt']));

        // Then
        static::assertSame(['at', 300, 'rt'], [$tokens->accessToken, $tokens->expiresIn, $tokens->refreshToken]);
    }

    #[Test]
    public function aTokenThatHasAlreadyExpiredIsRefused(): void
    {
        // Given
        $answer = new Document(['access_token' => 'at', 'token_type' => 'DPoP', 'expires_in' => 0]);

        // Then
        $this->expectException(RejectedAnswerException::class);

        // When
        TokenResponse::fromDocument($answer);
    }

    #[Test]
    public function aTokenWorthMoreThanAYearIsRefused(): void
    {
        // Given
        $answer = new Document(['access_token' => 'at', 'token_type' => 'DPoP', 'expires_in' => 1_000_000_000_000]);

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIs('The provider answered a token worth more than a year, which is no lifetime of an access token.');

        // When
        TokenResponse::fromDocument($answer);
    }

    /**
     * RFC 6749 §6: a refresh that answers no refresh token leaves the one held, and a scope it does not say is the one
     * originally granted.
     */
    #[Test]
    public function aRefreshThatAnswersNoRefreshTokenKeepsTheOneHeld(): void
    {
        // Given
        $held = TokenResponse::fromDocument(new Document([
            'access_token' => 'at',
            'token_type' => 'DPoP',
            'refresh_token' => 'rt',
            'scope' => 'openid profile',
        ]));

        // When
        $refreshed = TokenResponse::fromDocument(new Document(['access_token' => 'at2', 'token_type' => 'DPoP']))->asRefreshOf($held);

        // Then
        static::assertSame(['at2', 'rt', 'openid profile'], [$refreshed->accessToken, $refreshed->refreshToken, $refreshed->scope]);
    }

    /**
     * RFC 6749 §6: a new refresh token replaces the one held.
     */
    #[Test]
    public function aRefreshThatAnswersARefreshTokenReplacesTheOneHeld(): void
    {
        // Given
        $held = TokenResponse::fromDocument(new Document(['access_token' => 'at', 'token_type' => 'DPoP', 'refresh_token' => 'rt']));

        // When
        $refreshed = TokenResponse::fromDocument(new Document(['access_token' => 'at2', 'token_type' => 'DPoP', 'refresh_token' => 'rt2']))->asRefreshOf($held);

        // Then
        static::assertSame('rt2', $refreshed->refreshToken);
    }
}
