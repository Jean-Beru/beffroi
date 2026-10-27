<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Closure;
use DateTimeImmutable;
use Beffroi\Bundle\Http\PendingLoginStore;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Bundle\Tests\Functional\Key\DataKeyOutage;
use Beffroi\Bundle\Tests\Functional\Key\KmsOutage;
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
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
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
 * The acceptance of issue #128 (architecture §3.3, §5.4): a KMS that does not answer is a 503 with a
 * Retry-After wherever it stands on the path of a request, the code page, the token endpoint and the
 * enrolment of a TOTP; nothing is counted against the user, nothing is forgotten, the same request is
 * served once the KMS is back, and the audit sees the outage. The KMS of the kernel is taken down
 * between two requests by KmsOutage, and for the data keys of some families of columns alone by
 * DataKeyOutage; the secrets, the keys and the columns were sealed while it was up.
 *
 * The issuer the job runner presents the assertions of is declared by the test kernel, its keys the ones of
 * the suite, named before the kernel boots.
 */
final class KmsOutageTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * The name the trusted issuer knows alice by, which a linked identity of its source turns into her
     * account (decision 0002).
     */
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
     * RFC 7523 §3 (issue #876): the "jti" of an assertion is remembered once the key its token is signed with is
     * open, so the assertion a 503 answered is an assertion nobody exchanged. The same request, once the KMS is
     * back, is answered with a token and is never taken for a replay.
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

    /**
     * Issue #876: on a worker whose key is open already, what the KMS is asked at every token of the job runner
     * is the envelope of the person the token is about, and that envelope is sealed before the "jti" is
     * remembered too. The assertion the outage turned away is exchanged by the same request once the KMS is
     * back.
     */
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
     * Decision 0018 (issue #877): a column sealed under a data key the KMS does not open is an outage like a key
     * the KMS does not open, a 503 with a Retry-After, announced with the words of the KMS, and not an error of
     * the server. Here the person a code names, on a worker that opened the keys that sign and nothing else.
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
     * RFC 6749 §4.1.2 (issue #877): the session a code descends from, and the person it names with it, are read
     * before the code is consumed, so a data key of theirs the KMS does not open leaves the code to the same
     * request once it does, which is answered with the tokens and never taken for a replay.
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
     * The families a session and the person it names are sealed under, each with a data key of its own.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideTheFamiliesOfASession(): iterable
    {
        yield 'the session' => ['authentication_session'];
        yield 'the person' => ['user'];
    }

    /**
     * RFC 6749 §4.1.2 (issue #884): a code presented again is refused as a replay, an invalid_grant and not an
     * outage, while the KMS does not open the data keys its session and its person are sealed under: the person the
     * replay is announced for is read in the clear, so neither is opened once the grant is revoked.
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
     * RFC 6749 §4.1.2 (issue #884): the replay is announced with the refresh token it revoked and the person the code
     * was issued in the name of while the KMS does not open those data keys, so the journal keeps the act whole.
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
     * RFC 9700 §4.13.2 (issue #884): a rotated refresh token presented again is refused as a reuse, an invalid_grant
     * and not an outage, while the KMS does not open the data keys its session and its person are sealed under.
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
     * RFC 9700 §4.13.2 (issue #884): the reuse is announced with the family it revoked and the person the family
     * descends from while the KMS does not open those data keys: a token of a revoked family is refused before any
     * reuse is looked for, so this presentation is the only one that can tell it.
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
     * RFC 7009 §2.2 (issue #888): a refresh token given back is answered 200 while the KMS does not open the data
     * keys its session and its person are sealed under: the person the revocation is announced for is read in the
     * clear, so neither is opened once the token is revoked, and the client is not told to retry a revocation that
     * was done.
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
     * RFC 7009 §2.1 (issue #888): the revocation of a refresh token is announced with the person its session names
     * while the KMS does not open those data keys, so the journal keeps the act: a retry of the client finds the
     * token revoked already, answered 200 with nothing announced (§2.2), so this request is the only one that can
     * tell it.
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
     * RFC 7009 §2.2 (issue #888): an opaque access token given back is answered 200 while the KMS does not open the
     * data keys of the session it descends from and of the person that session names: the record names its person
     * by that session, whose subject is read in the clear once the token is removed.
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
     * RFC 7009 §2.1 (issue #888): the revocation of an opaque access token is announced with the person it was
     * issued in the name of while the KMS does not open those data keys: a retry of the client finds the token gone,
     * an unknown token answered 200 with nothing announced (§2.2), so this request is the only one that can tell it.
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

    /**
     * The code oidc-demo is given for alice, signed in and with a key to sign with, while the KMS answers.
     */
    private function codeOfAlice(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * A worker that opened nothing yet, neither a key nor a data key, behind every request from now on: the
     * kernel of the browser booted again for each one, as a worker that just started.
     */
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
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:' . self::DEMO_SECRET),
            ],
        );
    }

    /**
     * The refresh token the client that keeps its access offline gets for alice, signed in, while the KMS answers:
     * a public client, whose refresh token is rotated at every use (RFC 9700 §4.13.2).
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
     * The opaque access token the client of opaque tokens gets for alice, signed in, while the KMS answers: a token
     * the provider keeps a record of, which is what it can take back (RFC 7009 §2.1).
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
     * RFC 7009 §2.1: a client authenticated by its secret gives a token back.
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
     * RFC 7523 §2.1: the job runner, registered for tokens in the JWT shape, presents an assertion of the
     * trusted issuer for a token addressed to the calendar.
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
     * RFC 7523 §3: an assertion of the trusted issuer about the employee, addressed to this provider, under a
     * "jti" of its own.
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
