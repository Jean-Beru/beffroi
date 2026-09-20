<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Heidi\Core\Domain\Event\UserAuthenticated;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sleep;
use Symfony\Component\HttpFoundation\Response;

/**
 * The acceptance of issue #92 on the authorization endpoint (decision 0010, architecture §4.3), decided
 * per user since issue #110: a password session of a user who holds a passkey, asked for a class only a
 * passkey proves, is sent to the login page for the missing factor, the passkey proven on the same
 * session satisfies the request and the ID token says so; the same request from a user without a passkey
 * is refused before any page when essential, answered with what the session has when voluntary; a class
 * the tenant does not name is refused before any login; a login that satisfies nothing is the way back to
 * the client. The browser holds a session of the core signed in with a password.
 */
final class StepUpTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Decision 0010: essential or voluntary, a requested class the provider can prove, the session does
     * not satisfy and a passkey of the user would is a step-up, told to the page with the classes and the
     * kind of credential of the user that would do; the password form stays, it is the way back.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsForAPasskeyClass')]
    public function aPasswordSessionAskedForAPasskeyClassGetsTheLoginPageForTheMissingFactor(array $parameters): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize($parameters);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        $requirement = $crawler->filter('p[data-requirement]');
        static::assertSame('stronger_factor_required', $requirement->attr('data-requirement'));
        static::assertSame('phr', $requirement->attr('data-acr'));
        static::assertCount(1, $crawler->filter('p[data-step-up="passkey"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="password"]'));
        static::assertCount(1, $crawler->filter('form input[name="_password"]'));
        static::assertCount(1, $crawler->filter('form[data-passkey="login"]'));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideRequestsForAPasskeyClass(): iterable
    {
        yield 'essential, the claims parameter' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]];
        yield 'voluntary, acr_values' => [[
            'acr_values' => 'phr',
        ]];
        yield 'with prompt=login, as the re-authentication of Symfony sends it' => [[
            'acr_values' => 'phr',
            'prompt' => 'login',
        ]];
    }

    /**
     * Architecture §4.3: a user without a passkey can do nothing on the login page about an essential
     * "phr": the request goes back to the client as unmet_authentication_requirements before any page,
     * with the state and the issuer, as for a class the provider cannot prove.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideEssentialRequestsForAPasskeyClass')]
    public function aPasswordSessionWithoutAPasskeyAskedForAnEssentialPasskeyClassGoesBackToTheClientBeforeAnyPage(array $parameters): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', $parameters));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('unmet_authentication_requirements', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideEssentialRequestsForAPasskeyClass(): iterable
    {
        yield 'the claims parameter' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]];
        yield 'with prompt=login, before the page the prompt asks for' => [[
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
            'prompt' => 'login',
        ]];
    }

    /**
     * Architecture §4.3: a voluntary "phr" from a user without a passkey is answered at once with the
     * class the session has, "1" for a password; no page.
     */
    #[Test]
    public function aPasswordSessionWithoutAPasskeyAskedForAVoluntaryPasskeyClassGetsTheCodeAtOnceWithTheCurrentClass(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ]);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('1', $claims['acr']);
        static::assertSame(['pwd'], $claims['amr']);
    }

    /**
     * Architecture §4.3: with prompt=login, as the re-authentication of Symfony sends it, a voluntary
     * "phr" from a user without a passkey leaves the login the prompt asks for, and the page asks for a
     * new login, not for a factor the user does not have; the passkey form stays, a passkey enrolled
     * meanwhile on the account page satisfies the request, which is what castor demo --passkey plays.
     */
    #[Test]
    public function aPasswordSessionWithoutAPasskeyAskedForAVoluntaryPasskeyClassWithPromptLoginGetsAPlainReauthentication(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'acr_values' => 'phr',
            'prompt' => 'login',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('reauthentication_requested', $crawler->filter('p[data-requirement]')->attr('data-requirement'));
        static::assertCount(0, $crawler->filter('p[data-step-up]'));
        static::assertCount(1, $crawler->filter('form input[name="_password"]'));
        static::assertCount(1, $crawler->filter('form[data-passkey="login"]'));
    }

    /**
     * The third success criterion of the spike, on the provider's side: the passkey proven on the
     * password session during the step-up satisfies "phr", the ID token carries "acr" "phr", the methods
     * of both factors with "mfa" (RFC 8176 §2), "auth_time" moved to the passkey; one session on the OP,
     * no second one opened.
     */
    #[Test]
    public function thePasskeyProvenDuringTheStepUpSatisfiesTheRequestAndTheIdTokenSaysSo(): void
    {
        // Given
        self::signingKey();
        $device = self::device();
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->enrol($alice, $device, signedInAt: self::currentSecond()->modify('-10 minutes'));
        $first = $this->boundSession();
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->loginWithPasskey($interaction, $device);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ]);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('phr', $claims['acr']);
        static::assertSame(['pwd', 'hwk', 'user', 'mfa'], $claims['amr']);
        static::assertGreaterThan($first->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame($first->id->toRfc4122(), $claims['sid']);
        static::assertCount(1, self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    /**
     * OIDC Core §5.5.1.1: an essential class still unsatisfied after the login, the user having signed in
     * with the password again, goes back to the client as unmet_authentication_requirements, with the
     * state and the issuer; no second login page.
     */
    #[Test]
    public function anEssentialClassStillUnsatisfiedAfterTheLoginGoesBackToTheClient(): void
    {
        // Given
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}',
        ]);
        $this->aSecondLater();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('unmet_authentication_requirements', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * OIDC Core §5.5.1.1: a voluntary class still unsatisfied after the login is answered with the class
     * the session has, "1" for a password.
     */
    #[Test]
    public function aVoluntaryClassStillUnsatisfiedAfterTheLoginGetsTheCodeWithTheCurrentClass(): void
    {
        // Given
        self::signingKey();
        $this->enrol(self::userWithPassword('alice', self::PASSWORD), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->aSecondLater();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ]);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']));
        static::assertSame('1', $claims['acr']);
        static::assertSame(['pwd'], $claims['amr']);
    }

    /**
     * OIDC Core §3.1.2.6: prompt=none with a step-up is login_required, redirected.
     */
    #[Test]
    public function promptNoneWithAStepUpIsLoginRequired(): void
    {
        // Given
        $this->enrol(self::user('alice'), self::device(), signedInAt: self::currentSecond()->modify('-10 minutes'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'acr_values' => 'phr',
            'prompt' => 'none',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('login_required', self::redirectedQuery($response)['error']);
    }

    /**
     * A session that already satisfies the class asked for is not asked anything: the code at once,
     * with that class.
     */
    #[Test]
    public function aSessionSatisfyingTheClassAskedForGetsTheCodeAtOnce(): void
    {
        // Given
        $device = self::device();
        $this->enrol(self::user('alice'), $device);
        $this->forgetTheBrowser();
        $this->loginWithPasskey($this->authorize(), $device);

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo', [
            'acr_values' => 'phr',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertArrayHasKey('code', self::redirectedQuery($response));
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)
            ->selectButton('Sign in')
            ->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    /**
     * The clock of the kernel is the real one: a login has to be dated after the interaction it answers.
     */
    private function aSecondLater(): void
    {
        sleep(1);
    }
}
