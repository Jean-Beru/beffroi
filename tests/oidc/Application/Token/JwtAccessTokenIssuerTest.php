<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\EnvelopesThatThrow;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementRuntimeException;
use function array_keys;
use DateInterval;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FixedPairwiseSalt;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\PairwiseSaltBehindAnOutage;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function preg_match;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Uid\Uuid;

final class JwtAccessTokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private Jwts $jwts;

    private JwtAccessTokenIssuer $issuer;

    private SealedPerson $persons;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->jwts = new Jwts($this->session->tenant);
        $this->persons = Subjects::sealedPerson();
        $this->issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itMintsACompactJwsForTenMinutes(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token->value));
    }

    /**
     * RFC 9068 §2.1
     */
    #[Test]
    public function theHeaderNamesTheTypeAndTheActiveKey(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['header' => $header] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            [
                'typ' => 'at+jwt',
                'alg' => 'RS256',
                'kid' => $this->jwts->key->kid,
            ],
            $header,
        );
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aKmsThatDoesNotAnswerIsToldWhenTheTokenIsAddressed(): void
    {
        // Given
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signerBehindAnOutage(),
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The sealed key could not be opened.');

        // When
        $issuer->address($this->client);
    }

    #[Test]
    public function aTokenIsSignedWithTheKeyOpenedWhenItWasAddressed(): void
    {
        // Given
        $addressed = $this->issuer->address($this->client);
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signerBehindAnOutage(),
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = $issuer->issue($authorization, $addressed, Fixtures::now());

        // Then
        static::assertSame($this->jwts->key->kid, $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'))['header']['kid']);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aKmsThatDoesNotAnswerForThePairwiseSaltIsToldWhenTheTokenIsAddressed(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage();
        $salts->down = true;
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::bothKinds(salts: $salts),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs(PairwiseSaltBehindAnOutage::WORDS_OF_THE_KMS);

        // When
        $issuer->address(Clients::pairwise($this->session->tenant));
    }

    #[Test]
    public function aTokenOfAPairwiseClientNamesWhoeverSignedInByWhatWasOpenedWhenItWasAddressed(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage();
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::bothKinds(salts: $salts),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );
        $client = Clients::pairwise($this->session->tenant);
        $addressed = $issuer->address($client);
        $salts->down = true;
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = $issuer->issue($authorization, $addressed, Fixtures::now());

        // Then
        ['claims' => $claims] = $this->jwts->verify($token->value, 'pairwise-app', Fixtures::now()->modify('+9 minutes'));
        static::assertSame(
            Subjects::pairwiseKind(new FixedPairwiseSalt())->resolve($this->session->user, $client)->value,
            $claims['sub'] ?? null,
        );
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function aTokenAPairwiseClientHoldsForItselfAsksNothingOfThePairwiseSalt(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage();
        $salts->down = true;
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::bothKinds(salts: $salts),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            $this->persons,
        );
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            Clients::pairwiseService($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );

        // When
        $token = Tokens::accessToken($issuer, $authorization, Fixtures::now());

        // Then
        static::assertSame(
            'pairwise-batch',
            $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'))['claims']['sub'] ?? null,
        );
    }

    #[Test]
    public function aKmsThatDoesNotSealThePersonIsToldWhenTheTokenIsAddressed(): void
    {
        // Given
        $issuer = $this->issuerSealingWith(self::sealerBehindAnOutage());
        $authorization = $this->exchangedFor(Fixtures::user($this->session->tenant)->subject);

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('could not be sealed under the KMS key');

        // When
        $issuer->addressFor($authorization);
    }

    #[Test]
    public function aTokenCarriesThePersonSealedWhenItWasAddressed(): void
    {
        // Given
        $alice = Fixtures::user($this->session->tenant);
        $authorization = $this->exchangedFor($alice->subject);
        $addressed = $this->issuer->addressFor($authorization);
        $issuer = $this->issuerSealingWith(self::sealerBehindAnOutage());

        // When
        $token = $issuer->issue($authorization, $addressed, Fixtures::now());

        // Then
        $claims = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'))['claims'];
        static::assertSame($alice->subject->value, (string) $this->persons->of($this->session->tenant, $claims[JwtAccessTokenIssuer::PERSON] ?? null));
    }

    #[Test]
    public function aTokenWhosePersonWasNotSealedIsAFaultOfTheGrant(): void
    {
        // Given
        $authorization = $this->exchangedFor(Fixtures::user($this->session->tenant)->subject);
        $addressed = $this->issuer->address($authorization->client);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The person this access token is about was not sealed when it was addressed, before the grant spent what the request presented (architecture section 4.6).');

        // When
        $this->issuer->issue($authorization, $addressed, Fixtures::now());
    }

    #[Test]
    public function aTokenSomebodySignedInForIsAddressedWithoutSealing(): void
    {
        // Given
        $issuer = $this->issuerSealingWith(self::sealerBehindAnOutage());
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $token = Tokens::accessToken($issuer, $authorization, Fixtures::now());

        // Then
        static::assertArrayNotHasKey(JwtAccessTokenIssuer::PERSON, $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'))['claims']);
    }

    /**
     * RFC 9068 §2.2, §2.2.1, §2.2.3, RFC 8693 §4.2, Architecture §4.6
     */
    #[Test]
    public function thePayloadCarriesTheClaimsOfRfc9068InOrder(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile', 'email']);
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code);
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'acr', 'amr', 'scope', 'sid', 'grant_id'], array_keys($claims));
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame(Fixtures::now()->modify('+10 minutes')->getTimestamp(), $claims['exp']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['client_id']);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['iat']);
        static::assertIsString($claims['jti']);
        static::assertTrue(Uuid::isValid($claims['jti']));
        static::assertSame($this->session->authenticatedAt()->getTimestamp(), $claims['auth_time']);
        static::assertSame(['pwd'], $claims['amr']);
        static::assertSame('openid profile email', $claims['scope']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
        static::assertSame($code->grantId->toRfc4122(), $claims['grant_id']);
    }

    /**
     * RFC 9068 §2.2, RFC 6749 §4.4
     */
    #[Test]
    public function aTokenNobodySignedInForNamesTheClientAndCarriesNoSignIn(): void
    {
        // Given
        $client = Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'scope', 'grant_id'], array_keys($claims));
        static::assertSame('batch', $claims['sub']);
        static::assertSame('batch', $claims['client_id']);
        static::assertSame(Clients::CALENDAR, $claims['aud']);
        static::assertSame('invoices.read', $claims['scope']);
        static::assertSame($authorization->grantId->toRfc4122(), $claims['grant_id']);
    }

    /**
     * RFC 8693 §2.2.1, §4.1
     */
    #[Test]
    public function aTokenExchangedForAnotherNamesItsSubjectAndWhoHoldsIt(): void
    {
        // Given
        $gateway = Clients::gateway($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $signIn = new TokenSignIn($this->session->id, AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()));
        $authorization = new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $gateway,
            new Subject('alice-subject'),
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
            $signIn,
            new Actor(new Subject('gateway'), new Actor(new Subject('first-hop'))),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('gateway', $claims['client_id']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
        static::assertSame(
            [
                'sub' => 'gateway',
                'act' => [
                    'sub' => 'first-hop',
                ],
            ],
            $claims['act'],
        );
    }

    /**
     * RFC 8693 §1.3
     */
    #[Test]
    public function aTokenNobodyHoldsForItsSubjectCarriesNoActor(): void
    {
        // Given
        $gateway = Clients::gateway($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $gateway,
            new Subject('alice-subject'),
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey('act', $claims);
        static::assertArrayNotHasKey('sid', $claims);
    }

    /**
     * RFC 8693 §2.2.1
     */
    #[Test]
    public function aTokenExchangedForAnotherSaysWhoItIsAbout(): void
    {
        // Given
        $alice = Fixtures::user($this->session->tenant);
        $token = Tokens::accessToken($this->issuer, $this->exchangedFor($alice->subject), Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            $alice->subject->value,
            (string) $this->persons->of($this->session->tenant, $claims[JwtAccessTokenIssuer::PERSON] ?? null),
        );
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function aTokenExchangedForAnotherNamesThePersonToNobodyHoldingIt(): void
    {
        // Given
        $alice = Fixtures::user($this->session->tenant);
        $token = Tokens::accessToken($this->issuer, $this->exchangedFor($alice->subject), Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertStringNotContainsString($alice->subject->value, self::json($claims));
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function aTokenSomebodySignedInForCarriesNoPerson(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey(JwtAccessTokenIssuer::PERSON, $claims);
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function aTokenAClientHoldsForItselfCarriesNoPerson(): void
    {
        // Given
        $service = Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $service,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey(JwtAccessTokenIssuer::PERSON, $claims);
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aTokenOfAGrantWithDetailsCarriesThem(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details('acct-4711', ['read']);
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            authorizationDetails: $details,
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($details->toClaim(), $claims['authorization_details']);
    }

    #[Test]
    public function aTokenOfAGrantWithoutDetailsCarriesNone(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertArrayNotHasKey('authorization_details', $claims);
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aTokenNarrowedToASubsetOfTheDetailsCarriesThatSubset(): void
    {
        // Given
        $granted = new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]);
        $narrowed = AuthorizationDetailTypes::details('acct-0815');
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), authorizationDetails: $granted),
            authorizationDetails: $narrowed,
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, $this->client->registration->clientId, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($narrowed->toClaim(), $claims['authorization_details']);
    }

    /**
     * RFC 8693 §4.4
     */
    #[Test]
    public function aTokenOfAClientThatNamesWhoMayActForItCarriesThatName(): void
    {
        // Given
        $gateway = Clients::gateway(
            $this->session->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            mayAct: new MayAct(new Subject('backend')),
        );
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $gateway,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame(
            [
                'sub' => 'backend',
            ],
            $claims['may_act'],
        );
    }

    /**
     * RFC 8707 §2, RFC 9068 §2.2, RFC 7519 §4.1.3
     *
     * @param list<string> $resources
     * @param string|list<string> $audience
     */
    #[Test]
    #[DataProvider('provideAudiences')]
    public function theTokenIsAddressedToTheResourcesItWasAskedFor(array $resources, string|array $audience): void
    {
        // Given
        $client = Clients::public($this->session->tenant, resources: Clients::resources());
        $code = Tokens::code(
            'the-code',
            $client,
            $this->session,
            Fixtures::now(),
            resources: ResourceIndicators::of($resources),
        );
        $token = Tokens::accessToken($this->issuer, UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), $code), Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token->value, Clients::CALENDAR, Fixtures::now()->modify('+9 minutes'));

        // Then
        static::assertSame($audience, $claims['aud']);
        static::assertSame('spa', $claims['client_id']);
    }

    /**
     * @return iterable<string, array{list<string>, string|list<string>}>
     */
    public static function provideAudiences(): iterable
    {
        yield 'one resource' => [[Clients::CALENDAR], Clients::CALENDAR];
        yield 'two resources' => [
            [Clients::CALENDAR, Clients::CONTACTS],
            [Clients::CALENDAR, Clients::CONTACTS],
        ];
    }

    /**
     * RFC 7519 §4.1.7
     */
    #[Test]
    public function twoTokensNeverShareAJti(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $first = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());
        $second = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // Then
        static::assertNotSame(
            $this->jwts->verify($first->value, 'spa', Fixtures::now())['claims']['jti'],
            $this->jwts->verify($second->value, 'spa', Fixtures::now())['claims']['jti'],
        );
    }

    /**
     * RFC 9068 §2.2.1
     */
    #[Test]
    public function itWritesTheAuthenticationContextOfTheSession(): void
    {
        // Given
        $session = new AuthenticationSession(
            Uuid::v7(),
            $this->session->tenant,
            $this->session->user,
            Fixtures::now(),
            AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(
                new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD),
                Fixtures::now(),
            ),
            Fixtures::context(),
            Fixtures::now()->modify('+12 hours'),
        );
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame('2', $claims['acr']);
        static::assertSame(['pwd', 'otp', 'mfa'], $claims['amr']);
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function theScopeIsTheOneOfTheResponse(): void
    {
        // Given
        $authorization = UserAuthorization::fromRefreshToken(
            Grants::refreshToken(),
            Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), null, ['openid', 'profile']),
            new Scopes([new Scope('profile')]),
        );
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame('profile', $claims['scope']);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function theLifetimeIsConfigurable(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $issuer = new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            Subjects::sealedPerson(),
            new DateInterval('PT1M'),
        );

        // When
        $token = Tokens::accessToken($issuer, $authorization, Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 minute'), $token->expiresAt);
        static::assertSame(60, $token->expiresIn());
    }

    #[Test]
    public function aTokenIsRefusedOncePastItsLifetime(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken(
            new JwtAccessTokenIssuer(
                $this->jwts->signer,
                Subjects::publicKind(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
                Subjects::sealedPerson(),
                new DateInterval('PT1M'),
            ),
            $authorization,
            Fixtures::now(),
        );

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($token->value, 'spa', Fixtures::now()->modify('+61 seconds'));
    }

    /**
     * RFC 9068 §4
     */
    #[Test]
    public function theAudienceIsTheClient(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));
        $token = Tokens::accessToken($this->issuer, $authorization, Fixtures::now());

        // Then
        $this->expectException(InvalidClaimException::class);

        // When
        $this->jwts->verify($token->value, 'other', Fixtures::now());
    }

    /**
     * Architecture §4.6, OIDC Core §5.5
     */
    #[Test]
    public function itCarriesTheNamesOfTheClaimsAskedForFromUserInfo(): void
    {
        // Given
        $asked = ClaimsRequest::fromJson('{"userinfo":{"email":{"essential":true},"name":null},"id_token":{"picture":null}}');
        $token = Tokens::accessToken(
            $this->issuer,
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
                claims: $asked,
            )),
            Fixtures::now(),
        );

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(
            ['iss', 'exp', 'aud', 'sub', 'client_id', 'iat', 'jti', 'auth_time', 'acr', 'amr', 'scope', 'userinfo_claims', 'sid', 'grant_id'],
            array_keys($claims),
        );
        static::assertSame(['email', 'name'], $claims['userinfo_claims']);
        static::assertStringContainsString('"userinfo_claims":["email","name"]', Jwts::rawPayload($token->value));
    }

    /**
     * RFC 8705 §3.1, RFC 7800 §3.1
     */
    #[Test]
    public function itBindsTheTokenToWhatTheClientProved(): void
    {
        // Given
        $certificate = Certificates::client();
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $this->session, Fixtures::now()),
            CertificateConfirmation::ofCertificate($certificate),
        );

        // When
        $claims = $this->jwts->verify(Tokens::accessToken($this->issuer, $authorization, Fixtures::now())->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertSame(
            [
                'x5t#S256' => $certificate->x5tS256(),
            ],
            $claims['cnf'],
        );
    }

    /**
     * RFC 6750 §2
     */
    #[Test]
    public function aTokenOfAClientThatProvedNoKeyCarriesNoConfirmation(): void
    {
        // Given
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
        ));

        // When
        $claims = $this->jwts->verify(Tokens::accessToken($this->issuer, $authorization, Fixtures::now())->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertArrayNotHasKey('cnf', $claims);
    }

    #[Test]
    public function itCarriesNoUserinfoClaimsWhenTheRequestAskedForTheIdTokenOnly(): void
    {
        // Given
        $idTokenOnly = ClaimsRequest::fromJson('{"id_token":{"picture":null}}');
        $token = Tokens::accessToken(
            $this->issuer,
            UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
                'the-code',
                $this->client,
                $this->session,
                Fixtures::now(),
                claims: $idTokenOnly,
            )),
            Fixtures::now(),
        );

        // When
        $claims = $this->jwts->verify($token->value, 'spa', Fixtures::now())['claims'];

        // Then
        static::assertArrayNotHasKey('userinfo_claims', $claims);
    }

    /**
     * RFC 8693 §2.1
     */
    private function exchangedFor(Subject $person): SubjectAuthorization
    {
        return new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            Clients::gateway($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            new Subject('alice-to-the-first-client'),
            new Scopes([new Scope('invoices.read')]),
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
            person: $person,
        );
    }

    private function issuerSealingWith(SecretSealerInterface $sealer): JwtAccessTokenIssuer
    {
        return new JwtAccessTokenIssuer(
            $this->jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            Subjects::sealedPerson($sealer),
        );
    }

    private static function sealerBehindAnOutage(): SecretSealerInterface
    {
        return new EnvelopeSecretSealer(new EnvelopesThatThrow(new KeyManagementRuntimeException('Failed to reach the KMS.')), Keys::KMS_KEY_ID);
    }

    /**
     * @param array<array-key, mixed> $claims
     */
    private static function json(array $claims): string
    {
        return json_encode($claims, JSON_THROW_ON_ERROR);
    }
}
