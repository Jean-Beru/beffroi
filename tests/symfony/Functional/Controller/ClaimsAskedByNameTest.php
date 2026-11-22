<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_keys;
use function base64_encode;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §5.5, §3.1.2.4, RFC 7591 §2
 */
final class ClaimsAskedByNameTest extends BrowserTestCase
{
    private const string DEMO_SECRET = 'demo-secret-of-at-least-32-characters-long';

    private const string NATIVE_REDIRECT_URI = 'http://127.0.0.1/callback';

    /**
     * RFC 7591 §2, OIDC Core §5.5.1
     */
    #[Test]
    public function userInfoServesNoClaimNoScopeTheClientRegisteredStandsFor(): void
    {
        // Given
        $this->signIn(self::alice());
        $accessToken = self::string($this->tokensOfTheDemoClient('{"userinfo": {"email": null, "phone_number": null}}')['access_token'] ?? null);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(['sub', 'email'], array_keys(self::json($response)));
    }

    #[Test]
    public function theIdTokenCarriesNoClaimNoScopeTheClientRegisteredStandsFor(): void
    {
        // Given
        $this->signIn(self::alice());

        // When
        $tokens = $this->tokensOfTheDemoClient('{"id_token": {"email": null, "phone_number": null}}');

        // Then
        $claims = self::claimsOf(self::string($tokens['id_token'] ?? null));
        static::assertSame('alice@example.test', $claims['email'] ?? null);
        static::assertArrayNotHasKey('phone_number', $claims);
    }

    /**
     * OIDC Core §3.1.2.4
     */
    #[Test]
    public function theConsentPageListsAClaimAskedForByNameBeyondTheScopesOfTheRequest(): void
    {
        // Given
        $this->signIn(self::alice());
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'scope' => 'openid',
            'claims' => '{"userinfo": {"email": null}}',
        ]));

        // When
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);

        // Then
        static::assertSame(['email'], $crawler->filter('li[data-claim]')->extract(['data-claim']));
        static::assertSame('Email address', $crawler->filter('li[data-claim="email"]')->text());
    }

    /**
     * OIDC Core §3.1.2.4
     */
    #[Test]
    public function aConsentForTheScopesAloneIsAskedAgainForAClaimAskedForByName(): void
    {
        // Given
        $alice = self::alice();
        $this->signIn($alice);
        self::consents()->save(new Consent(Uuid::v7(), $alice, self::client('native-app'), new Scopes([Scope::openid()]), self::now()));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'scope' => 'openid',
            'claims' => '{"userinfo": {"email": null}}',
        ]));

        // Then
        static::assertStringStartsWith('/consent?', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theClaimAgreedToByNameIsHeldByTheConsent(): void
    {
        // Given
        $alice = self::alice();
        $this->signIn($alice);

        // When
        $this->allowTheNativeApplication('{"userinfo": {"email": null}}');

        // Then
        static::assertSame(['email'], self::consentOf($alice)->claims->all);
    }

    /**
     * OIDC Core §5.5
     */
    #[Test]
    public function userInfoServesTheClaimAgreedToByName(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::alice());
        $code = $this->allowTheNativeApplication('{"userinfo": {"email": null}}');
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::NATIVE_REDIRECT_URI,
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token'] ?? null);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(['sub', 'email'], array_keys(self::json($response)));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theAccountListsTheClaimsAConsentHoldsByName(): void
    {
        // Given
        $alice = self::alice();
        $this->signIn($alice);
        self::consents()
            ->save(new Consent(
                Uuid::v7(),
                $alice,
                self::client('native-app'),
                new Scopes([Scope::openid()]),
                self::now(),
                null,
                new ClaimNames(['email']),
            ));

        // When
        $crawler = $this->browser->request('GET', '/account/consents');

        // Then
        static::assertSame(['email'], $crawler->filter('tr[data-client="native-app"] li[data-claim]')->extract(['data-claim']));
    }

    /**
     * @return array<string, mixed>
     */
    private function tokensOfTheDemoClient(string $claims): array
    {
        self::signingKey();
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'scope' => 'openid',
            'claims' => $claims,
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The demonstration got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:' . self::DEMO_SECRET),
            ],
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    private function allowTheNativeApplication(string $claims): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'scope' => 'openid',
            'claims' => $claims,
        ]));
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The native application got no code.');
    }

    private static function alice(): User
    {
        $alice = self::user('alice');
        $alice->changeEmail(new EmailAddress('alice@example.test'), true, self::now());
        $alice->changePhoneNumber('+33612345678', true, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        return $alice;
    }

    private static function consents(): ConsentRepositoryInterface
    {
        return self::service('test.beffroi.consents', ConsentRepositoryInterface::class);
    }

    private static function consentOf(User $user): Consent
    {
        return (
            self::service('test.beffroi.active_consents', ActiveConsentsInterface::class)->activeOf($user)[0] ?? static::fail('The user has agreed to nothing.')
        );
    }
}
