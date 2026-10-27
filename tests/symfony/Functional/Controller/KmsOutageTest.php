<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Closure;
use DateTimeImmutable;
use Beffroi\Bundle\Http\PendingLoginStore;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Bundle\Tests\Functional\Key\KmsOutage;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use function intdiv;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use function str_replace;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * The acceptance of issue #128 (architecture §3.3, §5.4): a KMS that does not answer is a 503 with a
 * Retry-After wherever it stands on the path of a request, the code page, the token endpoint and the
 * enrolment of a TOTP; nothing is counted against the user, nothing is forgotten, the same request is
 * served once the KMS is back, and the audit sees the outage. The KMS of the kernel is taken down
 * between two requests by KmsOutage; the secrets and the keys were sealed while it was up.
 */
final class KmsOutageTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string PAIRWISE_REDIRECT_URI = 'https://pairwise.test/callback';

    private const string PAIRWISE_SECRET = 'pairwise-secret-of-at-least-32-characters';

    private KmsOutage $kms;

    private TotpSecret $secret;

    protected function setUp(): void
    {
        $this->kms = new KmsOutage();
        parent::setUp();
        $this->secret = Totps::secret();
    }

    protected function configureContainer(): Closure
    {
        return $this->kms->takeOver(...);
    }

    #[Test]
    public function theCodePageAnswersServiceUnavailableWithARetryAfter(): void
    {
        // Given
        $this->userWithTotp('alice');
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice');
        $this->kms->down = true;

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        static::assertSame((string) KmsUnavailableListener::RETRY_AFTER, $response->headers->get('Retry-After'));
    }

    /**
     * The refusal is the KMS's, not the user's: no failure of the login is announced, no code was used,
     * nothing is open, and the pending login waits for the code to be typed again.
     */
    #[Test]
    public function aCodeTheKmsCannotOpenIsNoFailureOfTheLogin(): void
    {
        // Given
        $alice = $this->userWithTotp('alice');
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice');
        $this->kms->down = true;

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertSame([], self::events(TotpUsed::class));
        static::assertFalse($this->isBoundToASession());
        static::assertSame([], self::sessionsOf('alice'));
        static::assertTrue($this->readHttpSession()->has(PendingLoginStore::KEY), 'The pending login was forgotten.');
        static::assertNull(self::totpOf($alice)->lastUsedAt);
    }

    /**
     * Architecture §3.5: the audit sees the outage as it happens, with the request it turned away and
     * the words of the KMS; nothing of the secret is in it.
     */
    #[Test]
    public function theOutageIsAnnouncedWithTheContextOfTheRequestAndTheWordsOfTheKms(): void
    {
        // Given
        $this->userWithTotp('alice');
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice');
        $this->kms->down = true;

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        $outages = self::events(KmsUnavailable::class);
        static::assertCount(1, $outages);
        static::assertSame('The sealed secret could not be opened. ' . KmsOutage::WORDS_OF_THE_KMS, $outages[0]->reason);
        static::assertSame('127.0.0.1', $outages[0]->context->ipAddress);
        static::assertTrue($outages[0]->tenant->equals(self::tenant()));
        static::assertStringNotContainsString(Base32::encodeUpperUnpadded(Totps::SEED), $outages[0]->reason);
    }

    /**
     * The same pending login and the same code once the KMS is back: the session is established with
     * both factors, as if nothing had happened.
     */
    #[Test]
    public function theSameCodePassesOnceTheKmsIsBack(): void
    {
        // Given
        $this->userWithTotp('alice');
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice');
        $code = $this->codeAt(new DateTimeImmutable());
        $this->kms->down = true;
        $this->submitCode($interaction, $code);
        $this->kms->down = false;

        // When
        $this->submitCode($interaction, $code);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        static::assertSame(['pwd', 'otp', 'mfa'], $this->boundSession()->methodReferences());
    }

    /**
     * Decision 0006 and architecture §3.4: the codes the KMS could not open cost the user none of their
     * five attempts a minute; the sixth code, the first the KMS opens, is the first counted.
     */
    #[Test]
    public function theCodesPostedDuringTheOutageCostNoAttempt(): void
    {
        // Given
        $this->userWithTotp('alice');
        $interaction = $this->authorize();
        $this->submitLogin($interaction, 'alice');
        $this->kms->down = true;
        for ($attempt = 1; $attempt <= 5; ++$attempt) {
            $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));
        }
        $this->kms->down = false;

        // When
        $this->submitCode($interaction, $this->codeAt(new DateTimeImmutable()));

        // Then
        static::assertSame(['pwd', 'otp', 'mfa'], $this->boundSession()->methodReferences());
        static::assertSame([], self::events(AuthenticationFailed::class));
    }

    /**
     * The token endpoint on a worker that has opened its signing key already, which is every worker after its first
     * signature, for a client that sees its users under an identifier of its sector (OIDC Core §8.1, issue #880): the
     * salt that identifier is computed with is the one thing the KMS is asked for, and a KMS that does not answer is
     * a 503 the client comes back from.
     */
    #[Test]
    public function theTokenEndpointAnswersServiceUnavailableOnAPairwiseSaltTheKmsDoesNotOpen(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->signInClient('pairwise-app', self::PAIRWISE_REDIRECT_URI, self::PAIRWISE_SECRET);
        $code = $this->pairwiseCode();
        $this->kms->down = true;

        // When
        $this->postPairwiseCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        static::assertSame((string) KmsUnavailableListener::RETRY_AFTER, $response->headers->get('Retry-After'));
        static::assertSame('The sealed secret could not be opened. ' . KmsOutage::WORDS_OF_THE_KMS, self::events(KmsUnavailable::class)[0]->reason ?? null);
    }

    /**
     * RFC 6749 §4.1.2 (issue #880): the salt is unsealed before the code is consumed, so the code a 503 answered is a
     * code nobody exchanged. The same request, once the KMS is back, is answered with the tokens, which name the
     * person by the identifier of the sector, and is never taken for a replay that would revoke the grant.
     */
    #[Test]
    public function theSameCodeOfAPairwiseClientIsExchangedOnceTheKmsIsBack(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->signInClient('pairwise-app', self::PAIRWISE_REDIRECT_URI, self::PAIRWISE_SECRET);
        $subject = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token'] ?? null))['sub'] ?? null;
        $code = $this->pairwiseCode();
        $this->kms->down = true;
        $this->postPairwiseCode($code);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        $this->kms->down = false;

        // When
        $this->postPairwiseCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertSame($subject, self::claimsOf(self::string(self::json($response)['id_token'] ?? null))['sub'] ?? null);
    }

    /**
     * The token endpoint on a worker that has not opened the key yet (the kernel of the browser is cold
     * on every request): the key sealed while the KMS was up cannot be opened, the client reads a 503
     * and comes back, the code it holds still unspent.
     */
    #[Test]
    public function theTokenEndpointAnswersServiceUnavailableOnAKeyTheKmsDoesNotOpen(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->kms->down = true;

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        static::assertSame((string) KmsUnavailableListener::RETRY_AFTER, $response->headers->get('Retry-After'));
        static::assertSame('The sealed key could not be opened. ' . KmsOutage::WORDS_OF_THE_KMS, self::events(KmsUnavailable::class)[0]->reason ?? null);
    }

    /**
     * RFC 6749 §4.1.2 (issue #870): the key that signs is opened before the code is consumed, so the code a 503
     * answered is a code nobody exchanged. The same request, once the KMS is back, is answered with the tokens
     * and is never taken for a replay that would revoke the grant.
     */
    #[Test]
    public function theSameCodeIsExchangedOnceTheKmsIsBack(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->kms->down = true;
        $this->postCode($code);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        $this->kms->down = false;

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertArrayHasKey('id_token', self::json($response));
    }

    /**
     * Architecture §5.2: the provisioning of an enrolment is sealed in the session before it is shown;
     * without the KMS there is nothing to show, and nothing is kept.
     */
    #[Test]
    public function beginningAnEnrolmentAnswersServiceUnavailable(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $form = $this->twoFactorPage()->selectButton('Set up an authenticator app')->form();
        $this->kms->down = true;

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        static::assertSame((string) KmsUnavailableListener::RETRY_AFTER, $response->headers->get('Retry-After'));
        static::assertFalse($this->readHttpSession()->has(TotpProvisioningStore::KEY));
    }

    /**
     * The first code of an enrolment while the KMS is down: the provisioning the session holds is not
     * forgotten, the same form confirms it once the KMS is back, the credential exists then and not before.
     */
    #[Test]
    public function theFirstCodeOfAnEnrolmentWaitsForTheKmsToBeBack(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $this->browser->submit($this->twoFactorPage()->selectButton('Set up an authenticator app')->form());
        $crawler = $this->afterTheForm();
        $this->secret = new TotpSecret(Base32::decodeUpper(str_replace(' ', '', $crawler->filter('code[data-two-factor="key"]')->text())));
        $form = $crawler->selectButton('Confirm')->form();
        $form['code'] = $this->codeAt(new DateTimeImmutable());
        $this->kms->down = true;
        $this->browser->submit($form);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        static::assertTrue($this->readHttpSession()->has(TotpProvisioningStore::KEY), 'The provisioning was forgotten.');
        static::assertSame([], self::events(CredentialEnrolled::class));
        $this->kms->down = false;

        // When
        $this->browser->submit($form);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertCount(1, self::events(CredentialEnrolled::class));
        static::assertCount(1, self::totpsOf($alice));
    }

    /**
     * A user with a password and a TOTP enrolled an hour ago on the secret of RFC 6238, sealed while the
     * KMS is up; the backup codes verify nothing.
     */
    private function userWithTotp(string $username): User
    {
        $user = self::userWithPassword($username, self::PASSWORD);
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

    private function submitLogin(string $interaction, string $username): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);
    }

    private function submitCode(string $interaction, string $code): void
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $form = $crawler->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    /**
     * A code of the client of a sector for alice, who is signed in.
     */
    private function pairwiseCode(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('pairwise-app', [
            'redirect_uri' => self::PAIRWISE_REDIRECT_URI,
        ]));

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client of the sector got no code.');
    }

    private function postPairwiseCode(string $code): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::PAIRWISE_REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('pairwise-app:' . self::PAIRWISE_SECRET),
            ],
        );
    }

    private function postCode(string $code): void
    {
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
    }

    private function twoFactorPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/two-factor');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $crawler;
    }

    /**
     * @return list<TotpCredential>
     */
    private static function totpsOf(User $user): array
    {
        self::reload();
        $managed = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');

        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($managed, TotpCredential::class);
    }

    private static function totpOf(User $user): TotpCredential
    {
        return self::totpsOf($user)[0] ?? static::fail('The credential is gone.');
    }
}
