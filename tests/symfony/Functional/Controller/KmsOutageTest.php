<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Closure;
use DateTimeImmutable;
use App\Doctrine\PersonalData\BlindIndexedColumns;
use App\Doctrine\PersonalData\EncryptedColumnTypes;
use App\Http\PendingLoginStore;
use App\Http\TotpProvisioningStore;
use App\Key\KeysOpenedAtStart;
use App\Key\KmsUnavailableListener;
use App\Messenger\KeysOpenedAtWorkerStart;
use App\Tests\Symfony\Functional\Key\DataKeyOutage;
use App\Tests\Symfony\Functional\Key\KmsOutage;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\MessageKeyProviderInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Event\RefreshTokenReuseDetected;
use Beffroi\Oidc\Domain\Event\TokenRevoked;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\TrustedIssuers;
use function intdiv;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_replace;
use Symfony\Component\Clock\Clock;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.3, §5.4
 */
final class KmsOutageTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string EMPLOYEE = 'employee-42';

    private const string PAIRWISE_REDIRECT_URI = 'https://pairwise.test/callback';

    private const string PAIRWISE_SECRET = 'pairwise-secret-of-at-least-32-characters';

    private const string OFFLINE_REDIRECT_URI = 'https://offline.test/callback';

    private const string DEMO_SECRET = 'demo-secret-of-at-least-32-characters-long';

    private const string OPAQUE_REDIRECT_URI = 'https://opaque.test/callback';

    private const string OPAQUE_SECRET = 'opaque-secret-of-at-least-32-characters-long';

    private KmsOutage $kms;

    private DataKeyOutage $dataKeys;

    private TotpSecret $secret;

    protected function setUp(): void
    {
        $this->kms = new KmsOutage();
        $this->dataKeys = new DataKeyOutage();
        $_SERVER['BEFFROI_TEST_TRUSTED_ISSUER_JWKS'] = base64_encode(json_encode(
            ['keys' => ClientAssertions::publishedKeys()->keys],
            JSON_THROW_ON_ERROR,
        ));
        parent::setUp();
        $this->secret = Totps::secret();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_TRUSTED_ISSUER_JWKS'], $_ENV['BEFFROI_TEST_TRUSTED_ISSUER_JWKS']);
    }

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $this->dataKeys->takeOver($container);
            $this->kms->takeOver($container);
        };
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
     * Architecture §3.5
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
     * Decision 0006, Architecture §3.4
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
     * OIDC Core §8.1
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
     * RFC 6749 §4.1.2
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
     * RFC 6749 §4.1.2
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
     * RFC 7523 §3
     */
    #[Test]
    public function theSameAssertionIsExchangedOnceTheKmsIsBack(): void
    {
        // Given
        self::signingKey();
        $this->linkTheEmployeeTo(self::user('alice'));
        $assertion = self::assertion();
        $this->kms->down = true;
        $this->postAssertion($assertion);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        $this->kms->down = false;

        // When
        $this->postAssertion($assertion);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertArrayHasKey('access_token', self::json($response));
    }

    #[Test]
    public function theAssertionWhosePersonTheKmsDidNotSealIsExchangedOnceTheKmsIsBack(): void
    {
        // Given
        $this->browser->disableReboot();
        self::signingKey();
        $this->linkTheEmployeeTo(self::user('alice'));
        $this->postAssertion(self::assertion());
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), 'The worker did not open its key.');
        $assertion = self::assertion();
        $this->kms->down = true;
        $this->postAssertion($assertion);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString('could not be sealed', self::events(KmsUnavailable::class)[0]->reason ?? '');
        $this->kms->down = false;

        // When
        $this->postAssertion($assertion);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertArrayHasKey('access_token', self::json($response));
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function aDataKeyTheKmsDoesNotOpenAnswersServiceUnavailableWithARetryAfter(): void
    {
        // Given
        $code = $this->codeOfAlice();
        $this->dataKeys->families = ['user'];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $response->getStatusCode());
        static::assertSame((string) KmsUnavailableListener::RETRY_AFTER, $response->headers->get('Retry-After'));
        static::assertSame(
            'The data key of a sealed value could not be opened. ' . KmsOutage::WORDS_OF_THE_KMS,
            self::events(KmsUnavailable::class)[0]->reason ?? null,
        );
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function theSameCodeIsExchangedOnceTheKmsOpensTheDataKeysItReads(string $family): void
    {
        // Given
        $code = $this->codeOfAlice();
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();
        $this->postCode($code);
        static::assertSame(Response::HTTP_SERVICE_UNAVAILABLE, $this->browser->getResponse()->getStatusCode());
        $this->dataKeys->families = [];

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertArrayHasKey('id_token', self::json($response));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTheFamiliesOfASession(): iterable
    {
        yield 'the session' => ['authentication_session'];
        yield 'the person' => ['user'];
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aReplayedCodeIsRefusedAsSuchWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $code = $this->codeOfAlice();
        $this->postCode($code);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), (string) $response->getContent());
        static::assertSame('invalid_grant', self::json($response)['error'] ?? null);
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aReplayedCodeIsAnnouncedWithWhatItRevokedWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $code = $this->codeOfAlice();
        $this->postCode($code);
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token'] ?? null);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postCode($code);

        // Then
        $replays = self::events(AuthorizationCodeReplayed::class);
        static::assertCount(1, $replays);
        static::assertSame('alice-subject', $replays[0]->subject->value);
        static::assertSame([DrawnSecret::digestOf($refreshToken)], $replays[0]->revokedTokenHashes);
    }

    /**
     * RFC 9700 §4.13.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aReusedRefreshTokenIsRefusedAsSuchWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $first = $this->refreshTokenOfTheOfflineClient();
        $this->postRefreshToken($first);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRefreshToken($first);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), (string) $response->getContent());
        static::assertSame('invalid_grant', self::json($response)['error'] ?? null);
    }

    /**
     * RFC 9700 §4.13.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aReusedRefreshTokenIsAnnouncedWithWhatItRevokedWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $first = $this->refreshTokenOfTheOfflineClient();
        self::aSecondLater();
        $this->postRefreshToken($first);
        $successor = self::string(self::json($this->browser->getResponse())['refresh_token'] ?? null);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRefreshToken($first);

        // Then
        $reuses = self::events(RefreshTokenReuseDetected::class);
        static::assertCount(1, $reuses);
        static::assertSame('alice-subject', $reuses[0]->subject->value);
        static::assertSame([DrawnSecret::digestOf($first), DrawnSecret::digestOf($successor)], $reuses[0]->revokedTokenHashes);
    }

    /**
     * RFC 7009 §2.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aRefreshTokenGivenBackIsAnsweredWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $this->postCode($this->codeOfAlice());
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token'] ?? null);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRevocation($refreshToken, 'oidc-demo', self::DEMO_SECRET);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
    }

    /**
     * RFC 7009 §2.1, §2.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function aRefreshTokenGivenBackIsAnnouncedWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $this->postCode($this->codeOfAlice());
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token'] ?? null);
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRevocation($refreshToken, 'oidc-demo', self::DEMO_SECRET);

        // Then
        $revocations = self::events(TokenRevoked::class);
        static::assertCount(1, $revocations);
        static::assertSame('alice-subject', $revocations[0]->subject?->value);
        static::assertSame(DrawnSecret::digestOf($refreshToken), $revocations[0]->tokenHash);
    }

    /**
     * RFC 7009 §2.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function anOpaqueAccessTokenGivenBackIsAnsweredWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $accessToken = $this->opaqueAccessTokenOfAlice();
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRevocation($accessToken, 'opaque-app', self::OPAQUE_SECRET);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
    }

    /**
     * RFC 7009 §2.1, §2.2
     */
    #[Test]
    #[DataProvider('provideTheFamiliesOfASession')]
    public function anOpaqueAccessTokenGivenBackIsAnnouncedWhileTheKmsDoesNotOpenTheDataKeysOfItsSession(string $family): void
    {
        // Given
        $accessToken = $this->opaqueAccessTokenOfAlice();
        $this->dataKeys->families = [$family];
        $this->aWorkerThatOpenedNothing();

        // When
        $this->postRevocation($accessToken, 'opaque-app', self::OPAQUE_SECRET);

        // Then
        $revocations = self::events(TokenRevoked::class);
        static::assertCount(1, $revocations);
        static::assertSame('alice-subject', $revocations[0]->subject?->value);
        static::assertSame(DrawnSecret::digestOf($accessToken), $revocations[0]->tokenHash);
    }

    /**
     * Architecture §5.2
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
     * The TOTP is enrolled on the secret of RFC 6238, sealed while the KMS is up.
     */
    /**
     * Decision 0018
     */
    #[Test]
    public function aThreadThatOpenedItsKeysAtStartExchangesACodeWhileTheKmsIsCut(): void
    {
        // Given
        $code = $this->codeOfAlice();
        $this->aThreadThatOpenedItsKeysAtStart();
        $this->kms->down = true;
        $this->dataKeys->families = [...EncryptedColumnTypes::families(), BlindIndexedColumns::SCOPE];

        // When
        $this->postCode($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), (string) $response->getContent());
        static::assertArrayHasKey('id_token', self::json($response));
    }

    /**
     * Decision 0020
     */
    #[Test]
    public function aConsumerThatOpenedItsKeysAtStartOpensABodyWhileTheKmsIsCut(): void
    {
        // Given
        $key = self::takeOver()->rotate(self::tenant(), Algorithms::messageSeal(), self::context());
        $this->aConsumerThatOpenedItsKeysAtStart();
        $this->kms->down = true;

        // When
        $opened = self::service('test.beffroi.key_provider', MessageKeyProviderInterface::class)->messageKey(self::tenant(), $key->kid);

        // Then
        static::assertSame($key->kid, $opened->key->kid);
    }

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

    private function codeOfAlice(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    private function aThreadThatOpenedItsKeysAtStart(): void
    {
        $this->aNewProcess();
        self::service(KeysOpenedAtStart::BY_A_THREAD, KeysOpenedAtStart::class)->open();
    }

    private function aConsumerThatOpenedItsKeysAtStart(): void
    {
        $this->aNewProcess();
        self::service(KeysOpenedAtWorkerStart::class, KeysOpenedAtWorkerStart::class)();
    }

    /**
     * A kernel booted anew, its doubles taken over by a first request that opens nothing.
     */
    private function aNewProcess(): void
    {
        $this->browser->getKernel()->shutdown();
        $this->browser->request('GET', '/jwks');
    }

    private function aWorkerThatOpenedNothing(): void
    {
        $this->browser->enableReboot();
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
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:' . self::DEMO_SECRET),
            ],
        );
    }

    /**
     * RFC 9700 §4.13.2
     */
    private function refreshTokenOfTheOfflineClient(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('offline-app', [
            'redirect_uri' => self::OFFLINE_REDIRECT_URI,
            'scope' => 'openid offline_access',
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client that keeps its access offline got no code.');
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::OFFLINE_REDIRECT_URI,
            'client_id' => 'offline-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        return self::string(self::json($this->browser->getResponse())['refresh_token'] ?? null);
    }

    private function postRefreshToken(string $refreshToken): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => 'offline-app',
        ]);
    }

    /**
     * RFC 7009 §2.1
     */
    private function opaqueAccessTokenOfAlice(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('opaque-app', [
            'redirect_uri' => self::OPAQUE_REDIRECT_URI,
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client of opaque tokens got no code.');
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::OPAQUE_REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('opaque-app:' . self::OPAQUE_SECRET),
            ],
        );

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    /**
     * RFC 7009 §2.1
     */
    private function postRevocation(string $token, string $clientId, string $secret): void
    {
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $token,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ],
        );
    }

    /**
     * RFC 7523 §2.1
     */
    private function postAssertion(string $assertion): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $assertion,
                'scope' => 'invoices.read',
                'resource' => 'https://cal.example.com/',
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('assertion-app:assertion-secret-of-at-least-32-character'),
            ],
        );
    }

    /**
     * RFC 7523 §3
     */
    private static function assertion(): string
    {
        return TrustedIssuers::assertion(self::EMPLOYEE, self::tenant()->issuer->value, Clock::get()->now(), [
            'jti' => Uuid::v4()->toRfc4122(),
        ]);
    }

    private function linkTheEmployeeTo(User $user): void
    {
        $now = Clock::get()->now();
        self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)
            ->save(new LinkedIdentity(Uuid::v7(), $user, TrustedIssuers::PROVIDER, self::EMPLOYEE, [], $now, $now));
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
