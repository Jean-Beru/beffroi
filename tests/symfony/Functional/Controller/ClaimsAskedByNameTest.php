<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

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
 * OIDC Core §5.5: a claim a client asks for by name is held to the scopes it registered, a client registering
 * scopes and never claims (RFC 7591 §2), and to what the person agreed to (§3.1.2.4), from the authorization
 * request to the two documents that tell it. The clients are the ones of the test kernel, which register
 * the scopes a declared client takes when it names none, "openid", "profile" and "email", and not "phone".
 */
final class ClaimsAskedByNameTest extends BrowserTestCase
{
    private const string DEMO_SECRET = 'demo-secret-of-at-least-32-characters-long';

    private const string NATIVE_REDIRECT_URI = 'http://127.0.0.1/callback';

    /**
     * RFC 7591 §2, OIDC Core §5.5.1: the phone number the demonstration asks for by name is not served,
     * and asking for it is no error; the email address it asks for beside it is, its scope being registered.
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

    /**
     * The same rule in the ID token: what a client may not be told by name is told in neither document.
     */
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
     * OIDC Core §3.1.2.4: the consent page lists by name the claim the request asks for that no scope of it
     * stands for, in the words the account says it in.
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
     * OIDC Core §3.1.2.4: a consent given for the scopes alone is not one for a claim the request asks for
     * by name beyond them, so the page is shown again instead of a code being issued on it.
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
     * Architecture §4.3: what the person agreed to by name is held by the consent beside its scopes.
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
     * OIDC Core §5.5: a claim agreed to by name is served without its scope, which is what asking for it by
     * name is for.
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
     * Architecture §5.2: the page of the account says what a consent holds by name, beside its scopes.
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
     * The code flow of the demonstration, which needs no consent, asking for "openid" alone and for the
     * claims given by name, under the signing key of the tenant: the token response.
     *
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

    /**
     * The native application asks for "openid" alone and for the claims given by name, and the person allows
     * it on the consent page: the code it is sent back with.
     */
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

    /**
     * Alice, with an address and a phone number, both verified.
     */
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
