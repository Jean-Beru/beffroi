<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Token\TokenSignIn;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class TokenSignInTest extends TestCase
{
    /**
     * OIDC Core §2, Front-Channel Logout §3: the four claims a token says its sign-in with, in the order
     * every token and every introspection response of the provider writes them.
     */
    #[Test]
    public function itWritesTheClaimsOfTheSignIn(): void
    {
        // Given
        $session = Uuid::v7();
        $signIn = new TokenSignIn($session, new AuthenticationSnapshot(new DateTimeImmutable('@1789466000'), ['pwd', 'otp'], '2'));

        // When
        $claims = $signIn->toClaims();

        // Then
        static::assertSame(
            [
                'auth_time' => 1789466000,
                'acr' => '2',
                'amr' => ['pwd', 'otp'],
                'sid' => $session->toRfc4122(),
            ],
            $claims,
        );
    }
}
