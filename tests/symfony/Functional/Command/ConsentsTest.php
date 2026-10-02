<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3, §5.5: the console takes back what a user agreed to let a client obtain, for an
 * administrator asked to do it for somebody. It takes back the same thing as the page of the account,
 * the rule being the use case's and not the command's.
 */
final class ConsentsTest extends ConsoleTestCase
{
    #[Test]
    public function theConsentOfTheUserForThatClientIsTakenBack(): void
    {
        // Given
        $user = self::user('alice');
        $client = self::client();
        self::consents()->save(new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now()));

        // When
        $tester = self::revoke('alice', 'oidc-demo');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull(self::consents()->findActive($user, $client));
    }

    #[Test]
    public function whatWasIssuedUnderTheConsentIsTakenBackWithIt(): void
    {
        // Given
        $user = self::user('alice');
        $client = self::client();
        $session = self::session($user);
        self::consents()->save(new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now()));
        $code = Tokens::code('the-code', $client, $session, self::now());
        self::codes()->save($code);
        $refreshToken = Tokens::refreshToken('the-refresh-token', $client, $session, self::now());
        self::refreshTokens()->save($refreshToken);
        $accessToken = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code)->storedUnder(
            DrawnSecret::digestOf('the-access-token'),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
        self::accessTokens()->save($accessToken);

        // When
        self::revoke('alice', 'oidc-demo');

        // Then
        static::assertTrue(self::codes()->findByCodeHash($code->codeHash)?->isRevoked());
        static::assertTrue(self::refreshTokens()->findByTokenHash($refreshToken->tokenHash)?->isRevoked());
        static::assertNull(self::accessTokens()->find('the-access-token'));
    }

    #[Test]
    public function aUserWhoGrantedNothingToThatClientIsToldSo(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::revoke('alice', 'oidc-demo');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('has granted nothing to "oidc-demo"', self::flattened($tester));
    }

    #[Test]
    public function aClientThatIsNotRegisteredIsRefused(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::revoke('alice', 'no-such-client');

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('No client "no-such-client" is registered', self::flattened($tester));
    }

    private static function revoke(string $username, string $clientId): CommandTester
    {
        return self::console('beffroi:user:revoke-consent', [
            'username' => $username,
            'client-id' => $clientId,
        ]);
    }

    private static function consents(): ConsentRepositoryInterface
    {
        return self::service('test.beffroi.consents', ConsentRepositoryInterface::class);
    }

    private static function codes(): AuthorizationCodeRepositoryInterface
    {
        return self::service('test.beffroi.authorization_codes', AuthorizationCodeRepositoryInterface::class);
    }

    private static function refreshTokens(): RefreshTokenRepositoryInterface
    {
        return self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class);
    }

    private static function accessTokens(): AccessTokenRepositoryInterface
    {
        return self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class);
    }
}
