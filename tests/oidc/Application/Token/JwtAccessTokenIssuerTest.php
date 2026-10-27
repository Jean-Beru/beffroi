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
     * Architecture §4.6: ten minutes from issuance, as a compact JWS.
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
     * RFC 9068 §2.1: header "typ" at+jwt, signed with the active key named by "kid". Verified by
     * jwt-library against the published JWKS, the way a resource server does.
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
     * Architecture §4.5 (issue #870): the key of the tenant the token is signed with is opened when the token
     * is addressed, so a KMS that does not answer is said then, before the grant spends anything.
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

    /**
     * Striking the token asks nothing of the KMS (issue #870): one addressed while the KMS answered is signed
     * with the key opened then, whatever the KMS answers once the grant has spent what the request presented.
     */
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
     * Architecture §4.5 (issue #880): the salt the "sub" of a pairwise client is computed with is unsealed when
     * the token is addressed, so a KMS that does not answer is said then, before the grant spends anything.
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

    /**
     * Striking the token asks nothing of the KMS (issue #880): the token of a pairwise client addressed while the
     * KMS answered names whoever signed in by the identifier of its sector, whatever the KMS answers once the
     * grant has spent what the request presented.
     */
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
     * RFC 6749 §4.4 (issue #880): a token a client holds for itself names that client, so addressing it opens no
     * kind of "sub" and the salt of a pairwise client is not asked for: a KMS that does not answer for it costs
     * that token nothing.
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

    /**
     * Issue #876: the person a token whose subject the client named is about is sealed when the token is
     * addressed, so a KMS that does not answer to seal it is said then, before the grant spends anything.
     */
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

    /**
     * Striking the token asks nothing of the KMS for the person either (issue #876): a token addressed while
     * the KMS answered carries the person sealed then, whatever the KMS answers once the grant has spent what
     * the request presented.
     */
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

    /**
     * A token whose person was not sealed when it was addressed is a fault of the grant that addressed it,
     * said before a token about that person leaves without saying so.
     */
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

    /**
     * A token somebody signed in for carries no person, so addressing it seals nothing and it is struck while
     * the KMS does not answer to seal.
     */
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
     * RFC 9068 §2.2: "iss", "exp", "aud", "sub", "client_id", "iat", "jti"; §2.2.1: "auth_time", "amr";
     * §2.2.3: "scope" as RFC 8693 §4.2 writes it; "sid" of the session and "grant_id" of the
     * authorization code the token descends from (architecture §4.6).
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
     * RFC 9068 §2.2, RFC 6749 §4.4: a token a client holds for itself names that client in "sub" and says
     * nothing of a sign-in, there having been none: no "sid", no "auth_time", no "acr", no "amr".
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
     * RFC 8693 §2.2.1, §4.1: a token somebody holds for its subject names the subject it was given and the
     * chain of actors that holds it, the most recent actor outermost, and carries the sign-in the token it
     * descends from named.
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
     * RFC 8693 §1.3: an impersonation says nothing of anybody acting, which is what tells it from a
     * delegation.
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
     * Issue #641: the "sub" of an exchanged token is the one the presented token carried, written for the
     * client that token had been issued to (RFC 8693 §2.2.1), so the token says who it is about beside it,
     * sealed, there being no record of it for the provider to read that from.
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
     * OIDC Core §8.1: the name the account carries is the one that links a person across sectors, and it is
     * what a pairwise kind exists to keep from a client, so nothing a client holds carries it. What the
     * provider wrote there it reads itself, and the holder of the token learns nothing from it.
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
     * A token somebody signed in for carries a "sub" the client it was written for reads back
     * (OIDC Core §8), so there is nothing beside it to write and no envelope to make on a sign-in.
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
     * RFC 6749 §4.4: a token a client holds for itself is about nobody, and it says so by carrying nothing
     * where a person would be named.
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
     * RFC 9396 §7: a token of a grant somebody agreed to details for carries the details of the response,
     * the array as it travelled and as an introspection renders it.
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

    /**
     * A grant nobody agreed to a detail for carries none, so the token says nothing of one rather than
     * saying it empty.
     */
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
     * RFC 9396 §7: the token carries the details of the response and not the ones the grant stands on, so a
     * request that narrowed them gets a token that carries the subset it asked for.
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
     * RFC 8693 §4.4: who may act for the subject of a token of this client, as its registration says it, so
     * that a resource server verifying the token offline reads the rule the provider applies.
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
     * RFC 8707 §2: the token is addressed to the resources the request asked it for, and "client_id"
     * goes on naming the client (RFC 9068 §2.2). One audience is written as a string and several as a
     * list (RFC 7519 §4.1.3).
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
     * RFC 7519 §4.1.7: two tokens never share a "jti".
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
     * RFC 9068 §2.2.1: "acr" as the session satisfies it, two factors here, "amr" with every method.
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
     * RFC 6749 §6: the scope of a refresh response is the narrowed one.
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
     * Architecture §4.6: the lifetime is a choice, ten minutes by default.
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

    /**
     * A token is refused once past its lifetime.
     */
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
     * RFC 9068 §4: "aud" is the client, so a token minted for one client fails the audience check of another.
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
     * Architecture §4.6: the names asked for by "claims.userinfo" (OIDC Core §5.5) travel in the token
     * as "userinfo_claims", in the order given, so that UserInfo serves them from the token alone; those
     * of "claims.id_token" do not.
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
     * RFC 8705 §3.1: a token issued on a request that proved a certificate carries the thumbprint of
     * that certificate in its "cnf" (RFC 7800 §3.1), which is what a resource server verifying the token
     * offline asks its caller to present again.
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
     * A client that proved nothing but who it is gets a bearer token, and a token that says so by
     * carrying no confirmation at all (RFC 6750 §2).
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

    /**
     * Nothing is written when the request asked for the ID token only.
     */
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
     * RFC 8693 §2.1: what a gateway is given for the subject of the token it presented, carrying the "sub"
     * that token carried and the person the exchange resolved when it read it (issue #601).
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

    /**
     * The issuer of the tests, sealing the persons of its tokens with that sealer.
     */
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

    /**
     * The sealer of the shared secrets in front of a KMS that cannot be reached, as a bridge of
     * symfony/key-management reports it.
     */
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
