<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use DateTimeImmutable;
use function intdiv;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Symfony\Component\Uid\Uuid;
use function str_replace;
use Symfony\Component\DomCrawler\Crawler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8628 and BCP 10027 over HTTP, end to end: an appliance with no keyboard asks for a code, shows it, and
 * polls; somebody types that code in a browser of their own, is asked to confirm, and the appliance gets its
 * tokens. One step per test.
 */
final class DeviceFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'appliance-app';

    private const string SECRET = 'appliance-secret-of-at-least-32-character';

    private const string PUBLIC_CLIENT_ID = 'appliance-public-app';

    private const string PASSWORD = 'correct horse battery staple';

    private TotpSecret $secret;

    protected function setUp(): void
    {
        parent::setUp();
        $this->secret = Totps::secret();
    }

    /**
     * RFC 8628 §3.2: the two codes, where the user goes, the same page with the code already in it (§3.3.1),
     * the lifetime and the interval.
     */
    #[Test]
    public function anApplianceIsAnsweredTwoCodesAPageAndTheTimes(): void
    {
        // When
        $this->ask();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $parameters = self::json($response);
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', self::string($parameters['device_code']));
        static::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', self::string($parameters['user_code']));
        static::assertSame('https://op.test/device', $parameters['verification_uri']);
        static::assertSame('https://op.test/device?user_code=' . self::string($parameters['user_code']), $parameters['verification_uri_complete']);
        static::assertSame(600, $parameters['expires_in']);
        static::assertSame(5, $parameters['interval']);
    }

    /**
     * RFC 8628 §3.2: the codes are credentials of one use and no cache holds them.
     */
    #[Test]
    public function theAnswerIsNeverCached(): void
    {
        // When
        $this->ask();

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * RFC 8628 §3.5: while nobody has answered, the client is told "not yet" and nothing else.
     */
    #[Test]
    public function aPollBeforeAnybodyAnsweredIsPending(): void
    {
        // Given
        $deviceCode = self::string(self::json($this->ask())['device_code']);

        // When
        $this->poll($deviceCode);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('authorization_pending', self::json($response)['error']);
    }

    /**
     * RFC 8628 §3.5: a client polling faster than the interval it was given is told to slow down.
     */
    #[Test]
    public function aPollFasterThanTheIntervalIsToldToSlowDown(): void
    {
        // Given
        $deviceCode = self::string(self::json($this->ask())['device_code']);
        $this->poll($deviceCode);

        // When
        self::aSecondLater();
        $this->poll($deviceCode);

        // Then
        static::assertSame('slow_down', self::json($this->browser->getResponse())['error']);
    }

    /**
     * RFC 8628 §3.5: past its lifetime the code is dead, and the appliance is told to start over.
     */
    #[Test]
    public function aPollAfterTheLifetimeIsToldTheCodeExpired(): void
    {
        // Given
        $deviceCode = self::string(self::json($this->ask())['device_code']);

        // When
        self::mockTime('+601 seconds');
        $this->poll($deviceCode);

        // Then
        static::assertSame('expired_token', self::json($this->browser->getResponse())['error']);
    }

    /**
     * RFC 8628 §3.3, BCP 10027 §2: the code typed by a signed-in user is answered with the request it names,
     * the client, where it came from, and what it asks for.
     */
    #[Test]
    public function theCodeTypedBySomebodySignedInNamesTheRequestAndWhatItAsksFor(): void
    {
        // Given
        $userCode = self::string(self::json($this->ask())['user_code']);
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->type($userCode);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString('Appliance with no keyboard', $crawler->filter('body')->text());
        static::assertSame(['openid', 'profile'], $crawler->filter('li[data-scope]')->extract(['data-scope']));
        static::assertSame(['op.test'], $crawler->filter('p[data-provider]')->extract(['data-provider']), 'BCP 10027 section 2: which provider is asking');
        static::assertCount(1, $crawler->filter('p[data-origin]'));
        static::assertCount(1, $crawler->filter('p[data-warning="unexpected"]'), 'BCP 10027 §2: somebody who started nothing is told to refuse');
    }

    /**
     * RFC 8628 §3.3: the whole flow. The code is typed and confirmed, and the appliance polling gets its
     * tokens, the ones of a code and nothing new.
     */
    #[Test]
    public function aConfirmedCodeReleasesTheTokensToThePollingAppliance(): void
    {
        // Given
        $answer = self::json($this->ask());
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        $this->approve(self::string($answer['user_code']));

        // When
        self::mockTime('+5 seconds');
        $this->poll(self::string($answer['device_code']));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $tokens = self::json($response);
        static::assertIsString($tokens['access_token']);
        static::assertIsString($tokens['id_token']);
        static::assertIsString($tokens['refresh_token']);
        static::assertSame('openid profile', $tokens['scope']);
        $claims = self::claimsOf(self::string($tokens['id_token']));
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame(self::CLIENT_ID, $claims['aud']);
    }

    /**
     * RFC 8628 §3.5: a device code is spent once, and presented again is worth nothing.
     */
    #[Test]
    public function aDeviceCodeSpentOnceIsRefusedAfterThat(): void
    {
        // Given
        $answer = self::json($this->ask());
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        $this->approve(self::string($answer['user_code']));
        self::mockTime('+10 seconds');
        $this->poll(self::string($answer['device_code']));

        // When
        self::mockTime('+20 seconds');
        $this->poll(self::string($answer['device_code']));

        // Then
        static::assertSame('invalid_grant', self::json($this->browser->getResponse())['error']);
    }

    /**
     * RFC 8628 §3.5: a user who refuses ends the request, and the appliance learns it rather than polling on.
     */
    #[Test]
    public function aRefusalEndsTheRequestAndTheApplianceLearnsIt(): void
    {
        // Given
        $answer = self::json($this->ask());
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        $this->answer(self::string($answer['user_code']), 'Refuse');

        // When
        self::mockTime('+10 seconds');
        $this->poll(self::string($answer['device_code']));

        // Then
        static::assertSame('access_denied', self::json($this->browser->getResponse())['error']);
    }

    /**
     * RFC 8628 §3.3.1: the complete verification URI brings the code already typed, and still asks for a
     * confirmation. A GET approves nothing, whatever it carries.
     */
    #[Test]
    public function theCompleteVerificationUriStillAsksForAConfirmation(): void
    {
        // Given
        $answer = self::json($this->ask());
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $this->browser->request('GET', '/device', [
            'user_code' => self::string($answer['user_code']),
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        self::mockTime('+10 seconds');
        $this->poll(self::string($answer['device_code']));
        static::assertSame('authorization_pending', self::json($this->browser->getResponse())['error'], 'the GET approved nothing');
    }

    /**
     * RFC 8628 §3.3: a request approved by nobody is a request approved by nobody. The visitor signs in on
     * the login of the firewall and lands back on the code the page carried.
     */
    #[Test]
    public function aVisitorWhoIsNotSignedInSignsInAndLandsBackOnTheCode(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $userCode = self::string(self::json($this->ask())['user_code']);

        // When
        $this->browser->request('GET', '/device', [
            'user_code' => $userCode,
        ]);

        // Then
        static::assertSame('/login', $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->followRedirect();
        $this->browser->submit($crawler
            ->selectButton('Sign in')
            ->form([
                '_username' => 'alice',
                '_password' => self::PASSWORD,
            ]));
        static::assertSame('/device?user_code=' . self::normalized($userCode), $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->followRedirect();
        static::assertCount(1, $crawler->filter('p[data-warning="unexpected"]'), 'the confirmation of the code the login came back with');
    }

    /**
     * The login of the firewall is the one every other page uses, second factor included: a password that is
     * not a login yet (§5.4) does not lose the page that was waiting for it.
     */
    #[Test]
    public function aUserWhoHoldsASecondFactorTypesTheirCodeAndLandsBackOnTheDeviceCode(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $userCode = self::string(self::json($this->ask())['user_code']);
        $this->browser->request('GET', '/device', [
            'user_code' => $userCode,
        ]);
        $crawler = $this->browser->followRedirect();

        // When
        $this->browser->submit($crawler
            ->selectButton('Sign in')
            ->form([
                '_username' => 'alice',
                '_password' => self::PASSWORD,
            ]));
        static::assertSame('/login/code', $this->browser->getResponse()->headers->get('Location'), 'the password is held until the code');
        $crawler = $this->browser->followRedirect();
        $form = $crawler->selectButton('Continue')->form();
        $form['_code'] = $this->codeAt(self::currentSecond());
        $this->browser->submit($form);

        // Then
        static::assertSame('/device?user_code=' . self::normalized($userCode), $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->followRedirect();
        static::assertCount(1, $crawler->filter('p[data-warning="unexpected"]'));
    }

    /**
     * RFC 8628 §3.3: a visitor who is not signed in is sent to the login before any code is read at all, so
     * that no code is ever tried by nobody.
     */
    #[Test]
    public function aVisitorWhoIsNotSignedInNeverReachesTheForm(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/device');

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame('/login', $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * BCP 10027 §2: the user compares the code on this page with the code on the screen of the appliance, so
     * it is shown the way that screen shows it whatever form it was typed in, separator included.
     */
    #[Test]
    public function theCodeIsShownBackAsTheApplianceShowsItWhateverFormItWasTypedIn(): void
    {
        // Given
        $userCode = self::string(self::json($this->ask())['user_code']);
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->type(strtolower(self::normalized($userCode)));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString($userCode, $crawler->filter('body')->text());
    }

    /**
     * RFC 8628 §5.1: a code that names no request awaiting an answer gets one refusal, whatever the reason it
     * names none.
     */
    #[Test]
    #[DataProvider('provideCodesThatNameNothing')]
    public function aCodeThatNamesNoRequestIsRefusedWithOneMessage(string $typed): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->type($typed);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(['unknown_code'], $crawler->filter('p[data-error]')->extract(['data-error']));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCodesThatNameNothing(): iterable
    {
        yield 'a code nobody issued' => ['ZXWV-TSRQ'];
        yield 'a value that is no code of ours' => ['not-a-code'];
    }

    /**
     * RFC 8628 §5.2, decision 0014: the codes refused to a user are counted, and guessing stops being
     * answered.
     */
    #[Test]
    public function repeatedWrongCodesStopBeingAnswered(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        for ($attempt = 0; $attempt < 6; ++$attempt) {
            $this->type('ZXWV-TSRQ');
        }

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertStringContainsString('too_many_attempts', self::string($response->getContent()));
    }

    /**
     * Decision 0014: only what was refused is counted, so a user who reads the same page of an appliance
     * several times over is never told to wait.
     */
    #[Test]
    public function aCodeThatNamesARequestCostsNoAttempt(): void
    {
        // Given
        $userCode = self::string(self::json($this->ask())['user_code']);
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        for ($attempt = 0; $attempt < 6; ++$attempt) {
            $this->type($userCode);
        }

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 8628 §3.1: a public client is what a television is, and it starts the flow by naming itself.
     */
    #[Test]
    public function aPublicApplianceStartsTheFlowByNamingItself(): void
    {
        // When
        $this->browser->request('POST', '/device_authorization', [
            'client_id' => self::PUBLIC_CLIENT_ID,
            'scope' => 'openid profile',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['device_code']);
    }

    /**
     * RFC 8628 §3.1: a client whose grants take no user on another device has no business here.
     */
    #[Test]
    public function aClientRegisteredForNoSuchGrantIsRefused(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/device_authorization',
            [
                'scope' => 'openid profile',
            ],
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );

        // Then
        static::assertSame('unauthorized_client', self::json($this->browser->getResponse())['error']);
    }

    /**
     * RFC 8628 §4: the endpoint and the grant are announced because they are wired.
     */
    #[Test]
    public function theDocumentAnnouncesTheEndpointAndTheGrant(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame('https://op.test/device_authorization', $metadata['device_authorization_endpoint']);
        $grants = $metadata['grant_types_supported'];
        static::assertIsArray($grants);
        static::assertContains('urn:ietf:params:oauth:grant-type:device_code', $grants);
    }

    private function ask(): Response
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/device_authorization',
            [
                'scope' => 'openid profile',
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );

        return $this->browser->getResponse();
    }

    private function poll(string $deviceCode): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code' => $deviceCode,
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );
    }

    private function type(string $userCode): Crawler
    {
        $crawler = $this->browser->request('GET', '/device');

        return $this->browser->submit($crawler
            ->selectButton('Continue')
            ->form([
                'user_code' => $userCode,
            ]));
    }

    private function approve(string $userCode): void
    {
        $this->answer($userCode, 'Allow');
    }

    private function answer(string $userCode, string $button): void
    {
        $crawler = $this->type($userCode);
        $this->browser->submit($crawler->selectButton($button)->form());
    }

    /**
     * A user who holds an active authenticator app, as the code page tests build one.
     */
    private function userWithTotp(string $username, string $password): User
    {
        $user = self::userWithPassword($username, $password);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $this->secret->bytes);
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $user,
                    $sealed,
                    Totps::credential($user, new FakePasswordHasher())->backupCodes,
                    intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                    $anHourAgo,
                ),
            );

        return $user;
    }

    private function codeAt(DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($this->secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    private static function normalized(string $userCode): string
    {
        return str_replace('-', '', $userCode);
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }
}
