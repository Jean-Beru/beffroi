<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Tests\Fixture\Fixtures;
use function base64_encode;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasskeyUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_repeat;
use function strlen;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * The acceptance of issue #90 on the login side (architecture §5.4): a passkey enrolled from a password
 * session signs in alone on the firewall of the interaction pages, the session of the core carries what
 * the assertion proved, the ID token carries the same; what is not a passkey of this tenant, signed for
 * this origin, over the challenge this browser got, is refused. The firewall is the one of
 * tests/symfony/config/config_test.yml, the authenticator of the browser a software one.
 */
final class PasskeyLoginTest extends PasskeyTestCase
{
    /**
     * The first success criterion of the spike: enrol from a password account, sign out, sign in with
     * the passkey alone. RFC 8176 §2 for the methods, architecture §3.2 for the classes.
     */
    /**
     * @param list<string> $methods
     */
    #[Test]
    #[DataProvider('provideDevices')]
    public function aPasskeyEnrolledFromAPasswordSessionSignsInAlone(SoftwareAuthenticator $device, array $methods, string $class): void
    {
        // Given
        $alice = self::userWithPassword('alice', 'correct horse battery staple');
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($alice->id));
        static::assertSame($methods, $session->methodReferences());
        static::assertSame($class, $session->authenticationContextClass()->value);
    }

    /**
     * @return iterable<string, array{SoftwareAuthenticator, list<string>, string}>
     */
    public static function provideDevices(): iterable
    {
        yield 'a hardware key without a PIN' => [self::device(), ['hwk', 'user'], 'phrh'];
        yield 'a hardware key with a PIN' => [self::device(userVerified: true), ['hwk', 'user', 'mfa'], 'phrh'];
        yield 'a synced passkey with user verification' => [self::device(userVerified: true, synced: true), ['swk', 'user', 'mfa'], 'phr'];
    }

    #[Test]
    public function theInteractionGoesOnAfterAPasskeyLogin(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->loginWithPasskey($interaction, $device);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * OIDC Core §2: "amr" and "acr" of the ID token are those of the session.
     */
    /**
     * @param list<string> $methods
     */
    #[Test]
    #[DataProvider('provideDevices')]
    public function theIdTokenCarriesWhatThePasskeyProved(SoftwareAuthenticator $device, array $methods, string $class): void
    {
        // Given
        self::signingKey();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->loginWithPasskey($interaction, $device);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
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
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame($methods, $claims['amr']);
        static::assertSame($class, $claims['acr']);
        static::assertSame($this->boundSession()->authenticatedAt()->getTimestamp(), $claims['auth_time']);
    }

    /**
     * The token of the firewall calls recent what the session proved (symfony/symfony#66064).
     */
    #[Test]
    public function theTokenOfTheFirewallCarriesTheProofsOfThePasskey(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $authenticatedAt = $this->boundSession()->authenticatedAt()->getTimestamp();
        static::assertSame(
            [
                'hwk' => $authenticatedAt,
                'user' => $authenticatedAt,
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    /**
     * Architecture §3.5 and WebAuthn Level 3 §7.2 step 26: the use is recorded on the passkey and announced.
     */
    #[Test]
    public function aPasskeyLoginIsRecordedOnThePasskeyAndAnnounced(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $passkey = self::passkeyOf($alice, $device);
        static::assertSame(1, $passkey->signCount);
        static::assertNotNull($passkey->lastUsedAt);
        $used = self::events(PasskeyUsed::class);
        static::assertCount(1, $used);
        static::assertTrue($used[0]->credential->id->equals($passkey->id));
        static::assertFalse($used[0]->signCountRegressed);
        static::assertSame('127.0.0.1', $used[0]->context->ipAddress);
        static::assertCount(1, self::events(UserAuthenticated::class));
    }

    /**
     * Architecture §3.2: a sign count that did not grow is told, not refused; a synced passkey keeps it at zero.
     */
    #[Test]
    public function aSignCountThatDidNotGrowIsToldNotRefused(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $this->loginWithPasskey($this->authorize(), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        self::forgetEvents();

        // When
        $this->loginWithPasskey($interaction, $device->withSignCount(0));

        // Then
        static::assertTrue($this->isBoundToASession());
        $used = self::events(PasskeyUsed::class);
        static::assertCount(1, $used);
        static::assertTrue($used[0]->signCountRegressed);
    }

    /**
     * OIDC Core §3.1.2.1 (prompt=login) and architecture §3.2: a passkey re-authenticates a password
     * session as a password does, its proofs recorded on the session the browser has, "auth_time" moved.
     */
    #[Test]
    public function aFreshLoginWithAPasskeyRecordsItsProofsOnThePasswordSession(): void
    {
        // Given
        $device = self::device();
        $alice = self::userWithPassword('alice', 'correct horse battery staple');
        $this->enrol($alice, $device, signedInAt: self::currentSecond()->modify('-10 minutes'));
        $first = $this->boundSession();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $session = $this->boundSession();
        static::assertTrue($session->id->equals($first->id));
        static::assertSame(['pwd', 'hwk', 'user', 'mfa'], $session->methodReferences());
        static::assertGreaterThan($first->authenticatedAt(), $session->authenticatedAt());
        static::assertSame('phrh', $session->authenticationContextClass()->value);
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
        static::assertCount(1, self::events(PasskeyUsed::class));
    }

    #[Test]
    public function aRevokedPasskeyIsRefused(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $passkey->revoke(self::now());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($passkey);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        $this->assertRefused($interaction);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::RevokedCredential, $failures[0]->reason);
        static::assertSame('hwk', $failures[0]->method?->value);
        static::assertNull($failures[0]->identifier);
        static::assertTrue($failures[0]->user?->id->equals($alice->id));
    }

    /**
     * WebAuthn Level 3 §6.1.3: the BE flag of a credential is set when it is created and never changes, so
     * an assertion that claims another one is refused after the signature, with the key the passkey was
     * enrolled as in the trail, and the row keeps that flag.
     */
    #[Test]
    public function anAssertionWhoseBackupEligibilityChangedIsRefused(): void
    {
        // Given
        $device = self::device(synced: true);
        $alice = self::user('alice');
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device->withoutBackupEligibility());

        // Then
        $failures = self::events(AuthenticationFailed::class);
        $this->assertRefused($interaction);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('swk', $failures[0]->method?->value);
        static::assertTrue($failures[0]->user?->id->equals($alice->id));
        static::assertTrue(self::passkeyOf($alice, $device)->backupEligible);
    }

    /**
     * The state of the account is checked after the signature, as after the password (UserChecker).
     */
    #[Test]
    public function aDisabledUserIsRefusedAfterTheSignature(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->enrol($alice, $device);
        $users = self::service('test.beffroi.users', UserRepositoryInterface::class);
        $managed = $users->find($alice->id) ?? static::fail('The user is gone.');
        $managed->disable(self::now());
        $users->save($managed);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        $this->assertRefused($interaction);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::DisabledUser, $failures[0]->reason);
        static::assertSame('hwk', $failures[0]->method?->value);
        static::assertTrue($failures[0]->user?->id->equals($alice->id));
    }

    /**
     * A passkey is a credential of one tenant (CredentialRepositoryInterface::findByExternalId()).
     */
    #[Test]
    public function aPasskeyOfAnotherTenantIsRefused(): void
    {
        // Given
        $device = self::device();
        $device->create($this->creationOptionsOfAnotherProvider());
        $other = new Tenant(Uuid::v7(), 'other', new Issuer('https://other.test'), 'Other', self::now());
        $bob = User::create(Uuid::v7(), $other, new Subject('bob-subject'), 'bob', self::now());
        self::entityManager()->persist($other);
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($bob);
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new PasskeyCredential(
                    Uuid::v7(),
                    $bob,
                    'Other key',
                    $device->credentialId,
                    $device->cosePublicKey(),
                    0,
                    ['usb'],
                    false,
                    false,
                    Uuid::v4(),
                    new PasskeyUserHandle($device->userHandle),
                    self::now(),
                ),
            );
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        $failures = self::events(AuthenticationFailed::class);
        $this->assertRefused($interaction);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertNull($failures[0]->method);
        static::assertNull($failures[0]->user);
    }

    /**
     * WebAuthn Level 3 §7.2, steps 13 and 15: the origin and the relying party of the assertion.
     */
    /**
     * @param callable(SoftwareAuthenticator): SoftwareAuthenticator $forge
     */
    #[Test]
    #[DataProvider('provideForgedAssertions')]
    public function anAssertionForAnotherOriginOrRelyingPartyIsRefused(callable $forge): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $forge($device));

        // Then
        $failures = self::events(AuthenticationFailed::class);
        $this->assertRefused($interaction);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertNull($failures[0]->method);
    }

    /**
     * @return iterable<string, array{callable(SoftwareAuthenticator): SoftwareAuthenticator}>
     */
    public static function provideForgedAssertions(): iterable
    {
        yield 'another origin' => [
            static fn (SoftwareAuthenticator $device): SoftwareAuthenticator => $device->atOrigin('https://phishing.example'),
        ];
        yield 'another relying party' => [
            static fn (SoftwareAuthenticator $device): SoftwareAuthenticator => $device->forRelyingParty('other.test'),
        ];
    }

    /**
     * WebAuthn Level 3 §13.4.3: a challenge is answered once.
     */
    #[Test]
    public function anAssertionIsAnsweredOnce(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $token = $this->loginPage($interaction)->filter('form[data-passkey="login"] input[name="_csrf_token"]')->attr('value');
        $assertion = $device->get($this->requestOptions($interaction));
        $this->postPasskeyLogin($interaction, $assertion, $token);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $token = $this->loginPage($interaction)->filter('form[data-passkey="login"] input[name="_csrf_token"]')->attr('value');

        // When
        $this->postPasskeyLogin($interaction, $assertion, $token);

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class), 'A replay without a pending ceremony is not an attempt on an account.');
        $this->assertRefused($interaction);
    }

    #[Test]
    public function aLoginWithoutItsTokenIsRefused(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->loginPage($interaction);

        // When
        $this->postPasskeyLogin($interaction, $device->get($this->requestOptions($interaction)), 'not-the-token');

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
        $this->assertRefused($interaction);
    }

    #[Test]
    public function theLoginPageOffersThePasskeyNextToTheForm(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('username webauthn', $crawler->filter('input[name="_username"]')->attr('autocomplete'));
        $passkey = $crawler->filter('form[data-passkey="login"]');
        static::assertCount(1, $passkey);
        static::assertSame('/login/passkey?interaction=' . $interaction, $passkey->attr('action'));
        static::assertSame('/login/passkey/options?interaction=' . $interaction, $passkey->attr('data-options-url'));
        static::assertNotNull($passkey->attr('hidden'), 'The passkey form waits for the script to find a capable browser.');
        static::assertCount(1, $passkey->filter('button[type="button"][data-passkey-button]'));
        static::assertSame('/passkey.js', $crawler->filter('script')->attr('src'));
        static::assertCount(
            1,
            $crawler->filter('form')->first()->filter('button[type="submit"]'),
            'The password form comes first: the scripted browser of the conformance suite clicks the first submit button.',
        );
    }

    /**
     * WebAuthn Level 3 §5.5: no user named, no allow list, the relying party of the tenant.
     */
    #[Test]
    public function theOptionsOfTheLoginPageAreForADiscoverableCredential(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->browser->request('POST', '/login/passkey/options?interaction=' . $interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        self::assertInteractionHeaders($response);
        $options = json_decode(self::string($response->getContent()), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($options);
        static::assertSame('op.test', $options['rpId']);
        static::assertSame([], $options['allowCredentials']);
        static::assertSame('preferred', $options['userVerification']);
        static::assertSame(43, strlen(self::string($options['challenge'])));
    }

    #[Test]
    public function theOptionsOfTheLoginPageNeedAnInteractionOfThisBrowser(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->forgetTheBrowser();

        // When
        $this->browser->request('POST', '/login/passkey/options?interaction=' . $interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame(
            [
                'error' => 'unknown_interaction',
            ],
            self::json($response),
        );
    }

    /**
     * The password still signs in on the same page: the passkey changes nothing for the form.
     */
    #[Test]
    public function thePasswordStillSignsInNextToThePasskey(): void
    {
        // Given
        $alice = self::userWithPassword('alice', 'correct horse battery staple');
        $this->enrol($alice, self::device());
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = 'correct horse battery staple';

        // When
        $this->browser->submit($form);

        // Then
        static::assertSame(['pwd'], $this->boundSession()->methodReferences());
    }

    /**
     * Back to the login page with the one message, no session bound.
     */
    private function assertRefused(string $interaction): void
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertCount(1, $this->loginPage($interaction)->filter('p[data-error="authentication_failed"]'));
    }

    /**
     * Options another provider drew: what the device answers with is no passkey of this tenant.
     */
    private function creationOptionsOfAnotherProvider(): string
    {
        return (
            '{"rp":{"id":"op.test","name":"Other"},"user":{"id":"'
            . Base64UrlSafe::encodeUnpadded(Fixtures::userHandle()->value)
            . '","name":"bob","displayName":"bob"},"challenge":"'
            . str_repeat('A', 43)
            . '","pubKeyCredParams":[{"type":"public-key","alg":-7}]}'
        );
    }
}
