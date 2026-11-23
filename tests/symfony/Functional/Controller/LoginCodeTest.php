<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_map;
use function base64_encode;
use DateTimeImmutable;
use App\Http\PendingLoginStore;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\BackupCodeUsed;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\PendingLogin;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use function intdiv;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use function sprintf;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2, §5.4
 */
final class LoginCodeTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string BACKUP_CODE_REFUSED = 'This backup code is wrong or already used.';

    private TotpSecret $secret;

    protected function setUp(): void
    {
        parent::setUp();
        $this->secret = Totps::secret();
    }

    #[Test]
    public function aUserWithoutATotpSignsInWithThePasswordAlone(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['pwd'], $this->boundSession()->methodReferences());
    }

    /**
     * Architecture §5.4
     */
    #[Test]
    public function aUserWithATotpIsAskedForACodeAfterAGoodPassword(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);
        static::assertSame('/login/code?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Decision 0006, Architecture §3.2
     */
    #[Test]
    public function nothingIsOpenedBeforeTheCode(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        $httpSession = $this->readHttpSession();
        static::assertFalse($this->isBoundToASession());
        static::assertFalse($httpSession->has('_security_beffroi_interaction'), 'The firewall kept a token of the first step.');
        $pending = $httpSession->get(PendingLoginStore::KEY);
        static::assertInstanceOf(PendingLogin::class, $pending);
        static::assertTrue($pending->userId->equals($alice->id));
        static::assertSame(['pwd'], array_map(static fn ($method): string => (string) $method, $pending->methods));
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    #[Test]
    public function aWrongPasswordAsksForNoCode(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->submitLogin($interaction, 'alice', 'not the password');

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->readHttpSession()->has(PendingLoginStore::KEY));
    }

    #[Test]
    public function theCodePageShowsItsFormToTheBrowserThatTypedThePassword(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $crawler = $this->codePage($interaction);

        // Then
        $response = $this->browser->getResponse();
        self::assertInteractionHeaders($response);
        $form = $crawler->filter('form[data-login="code"]');
        static::assertSame('/login/code?interaction=' . $interaction, $form->attr('action'));
        static::assertCount(1, $form->filter('input[name="_code"]'));
        static::assertCount(1, $form->filter('input[name="_csrf_token"]'));
        static::assertCount(0, $crawler->filter('input[name="_password"]'));
        static::assertCount(0, $crawler->filter('p[data-error]'));
    }

    #[Test]
    public function theCodePageWithoutAPendingLoginGoesBackToTheLoginPage(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function anotherBrowserCannotSeeTheCodePageOfAnInteraction(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->forgetTheBrowser();

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Architecture §3.2, §5.4, RFC 8176 §2
     */
    #[Test]
    public function aGoodCodeEstablishesTheSessionWithBothFactors(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        $session = $this->boundSession();
        static::assertTrue($session->user->id->equals($alice->id));
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
        static::assertSame('2', $session->authenticationContextClass()->value);
        static::assertCount(1, self::sessionsOf('alice'));
        static::assertFalse($this->readHttpSession()->has(PendingLoginStore::KEY), 'The pending login was not forgotten.');
    }

    #[Test]
    public function theTokenOfTheFirewallCarriesBothProofs(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $authTime = $this->boundSession()->authenticatedAt()->getTimestamp();
        static::assertSame(
            [
                'pwd' => $authTime,
                'otp' => $authTime,
            ],
            $this->securityToken()->getAuthenticationProofs(),
        );
    }

    #[Test]
    public function aCodePostedWithoutOriginOrRefererOpensASession(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $form = $this->codePage($interaction)->selectButton('Continue')->form();
        $form['_code'] = $this->codeAt(new DateTimeImmutable());

        // When
        $this->postedWithoutOriginOrReferer($form);

        // Then
        static::assertTrue($this->boundSession()->user->id->equals($alice->id));
    }

    /**
     * Architecture §3.4, §3.5
     */
    #[Test]
    public function aGoodCodeIsAnnouncedAndDatesBothCredentials(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertCount(1, self::events(TotpUsed::class));
        static::assertCount(0, self::events(BackupCodeUsed::class));
        static::assertCount(1, self::events(PasswordUsed::class));
        static::assertCount(1, self::events(UserAuthenticated::class));
        static::assertNotNull(self::credentialOf($alice, PasswordCredential::class)->lastUsedAt);
        static::assertNotNull(self::credentialOf($alice, TotpCredential::class)->lastUsedAt);
    }

    #[Test]
    public function theIdTokenCarriesBothFactorsAndTheTwoFactorClass(): void
    {
        // Given
        self::signingKey();
        $this->userWithTotp('alice', self::PASSWORD);
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));
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
        static::assertSame('2', $claims['acr']);
        static::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    #[Test]
    public function aBackupCodeEstablishesTheSession(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        static::assertSame(['pwd', 'otp', 'mfa'], $this->boundSession()->methodReferences());
        static::assertCount(1, self::events(BackupCodeUsed::class));
        static::assertCount(0, self::events(TotpUsed::class));
    }

    #[Test]
    public function aBackupCodeWorksOnce(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame(AuthenticationFailureReason::InvalidCredential, self::events(AuthenticationFailed::class)[0]->reason ?? null);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aWrongCodeGoesBackToTheCodePage(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login/code?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame('code_refused', $this->codePage($interaction)->filter('p[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §3.4
     */
    #[Test]
    public function aWrongCodeIsAnnouncedOnceWithItsReason(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $failures = self::events(AuthenticationFailed::class);
        static::assertCount(1, $failures);
        static::assertSame(AuthenticationFailureReason::InvalidCredential, $failures[0]->reason);
        static::assertSame('otp', (string) $failures[0]->method);
        static::assertTrue($failures[0]->user?->id->equals($alice->id));
    }

    #[Test]
    public function aRefusedAppCodeSaysToTryTheCodeTheAppShowsNow(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, '000000');

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('code_refused', $refusal->attr('data-error'));
        static::assertSame('Wrong code. Enter the code shown now.', $refusal->text());
    }

    #[Test]
    public function aRefusedBackupCodeSaysEachBackupCodeServesOnce(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, Totps::BACKUP_CODES[3]);

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('backup_code_refused', $refusal->attr('data-error'));
        static::assertSame(self::BACKUP_CODE_REFUSED, $refusal->text());
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aBackupCodeThatNeverExistedIsRefusedLikeASpentOne(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD, hashedBackupCodes: true);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // When
        $this->submitCode($interaction, 'ZZZZZ-ZZZZZ');

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('backup_code_refused', $refusal->attr('data-error'));
        static::assertSame(self::BACKUP_CODE_REFUSED, $refusal->text());
    }

    /**
     * Decision 0006, Architecture §5.4
     */
    #[Test]
    public function theSixthWrongCodeInAMinuteIsRefusedEvenWhenRight(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitCode($interaction, '000000');
        }
        self::forgetEvents();

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame(AuthenticationFailureReason::TooManyAttempts, self::events(AuthenticationFailed::class)[0]->reason ?? null);
    }

    #[Test]
    public function theCodeRefusedByTheLimitSaysToWait(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitCode($interaction, '000000');
        }

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $refusal = $this->refusalShown($interaction);
        static::assertSame('too_many_attempts', $refusal->attr('data-error'));
        static::assertSame('Too many attempts. Wait a moment, then try again.', $refusal->text());
    }

    #[Test]
    public function anAuthorizationRequestBetweenThePasswordAndTheCodeGetsNoCode(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $this->submitLogin($this->authorize(), 'alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
        static::assertCount(1, $this->loginPage($interaction)->filter('input[name="_password"]'));
    }

    #[Test]
    public function aCodePostedWithoutAPendingLoginOpensNothing(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();

        // When
        $this->browser->request('POST', '/login/code?interaction=' . $interaction, [
            '_code' => $this->codeAt(new DateTimeImmutable()),
            '_csrf_token' => 'whatever',
        ]);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        static::assertSame([], self::sessionsOf('alice'));
        static::assertSame([], self::events(AuthenticationFailed::class), 'Nothing was tried on an account.');
    }

    /**
     * Architecture §5.4
     */
    #[Test]
    public function anExpiredPendingLoginIsRefusedAndAsksForThePasswordAgain(): void
    {
        // Given
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorize();
        $this->holdExpiredLogin($alice);

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()), fromThePage: false);

        // Then
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertFalse($this->isBoundToASession());
        $refused = self::events(AuthenticationFailed::class);
        static::assertCount(1, $refused);
        static::assertSame(AuthenticationFailureReason::ExpiredLogin, $refused[0]->reason);
        static::assertSame('alice', $refused[0]->identifier);
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * OIDC Core §3.1.2.1, Architecture §3.2, RFC 6238 §5.2
     */
    #[Test]
    public function aFreshLoginOfATotpUserGoesThroughTheCodeAgain(): void
    {
        // Given
        self::mockTime(self::currentSecond());
        $this->userWithTotp('alice', self::PASSWORD);
        $first = $this->authorize();
        $this->submitLogin($first, 'alice', self::PASSWORD);
        $this->submitCode($first, $this->codeAt(Clock::get()->now()));
        $session = $this->boundSession();
        self::aSecondLater();
        $interaction = $this->authorize([
            'prompt' => 'login',
        ]);
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        static::assertSame('/login/code?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        self::forgetEvents();

        // When
        $this->submitCode($interaction, $this->codeAt(Clock::get()->now()->modify(sprintf('+%d seconds', TotpCredential::PERIOD))));

        // Then
        static::assertCount(1, self::sessionsOf('alice'));
        $refreshed = $this->boundSession();
        static::assertTrue($refreshed->id->equals($session->id));
        static::assertGreaterThan($session->authenticatedAt(), $refreshed->authenticatedAt());
        static::assertSame([], self::events(UserAuthenticated::class), 'No session was opened.');
    }

    /**
     * Architecture §3.2
     */
    #[Test]
    public function aPasskeyLoginOfATotpUserAsksForNoCode(): void
    {
        // Given
        $device = self::device();
        $alice = $this->userWithTotp('alice', self::PASSWORD);
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['hwk', 'user'], $this->boundSession()->methodReferences());
    }

    /**
     * Decision 0010, Architecture §4.3
     */
    #[Test]
    public function theStepUpToTwoFactorsNamesTheCodeOfTheUserWhoHoldsATotp(): void
    {
        // Given
        $this->signIn($this->userWithTotp('alice', self::PASSWORD), self::currentSecond()->modify('-10 minutes'));
        $interaction = $this->authorize([
            'acr_values' => '2',
        ]);

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame('2', $crawler->filter('p[data-requirement]')->attr('data-acr'));
        static::assertCount(1, $crawler->filter('p[data-step-up="totp"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="password"]'));
        static::assertCount(0, $crawler->filter('p[data-step-up="passkey"]'));
    }

    /**
     * The TOTP is on the secret of RFC 6238; the backup codes verify only with $hashedBackupCodes.
     */
    private function userWithTotp(string $username, string $password, bool $hashedBackupCodes = false): User
    {
        $user = self::userWithPassword($username, $password);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $this->secret->bytes);
        $hasher = $hashedBackupCodes ? self::service('test.beffroi.password_hasher', PasswordHasherInterface::class) : new FakePasswordHasher();
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $user,
                    $sealed,
                    Totps::credential($user, $hasher)->backupCodes,
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

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    private function codePage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    private function refusalShown(string $interaction): Crawler
    {
        $refusals = $this->codePage($interaction)->filter('p[data-error]');
        static::assertCount(1, $refusals);

        return $refusals;
    }

    private function submitCode(string $interaction, string $code, bool $fromThePage = true): void
    {
        if (! $fromThePage) {
            $token = $this->loginPage($interaction)->filter('input[name="_csrf_token"]')->attr('value');
            $this->browser->request('POST', '/login/code?interaction=' . $interaction, [
                '_code' => $code,
                '_csrf_token' => $token,
            ]);

            return;
        }
        $form = $this->codePage($interaction)->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    private function holdExpiredLogin(User $user): void
    {
        $this->httpSession(static function (SessionInterface $httpSession) use ($user): void {
            $provenAt = new DateTimeImmutable('-1 hour');
            new PendingLoginStore()->hold(
                $httpSession,
                new PendingLogin($user->id, [AuthenticationMethod::password()], $provenAt, $provenAt->modify('+5 minutes')),
            );
        });
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return T
     */
    private static function credentialOf(User $user, string $kind): object
    {
        self::reload();
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return (
            self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
                ->findByUser($managed, $kind)[0] ?? static::fail('The credential is gone.')
        );
    }
}
