<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Tests\Fixture\Grants;
use function array_keys;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Token\StoredClientAccessToken;
use Heidi\Oidc\Domain\Token\StoredUserAccessToken;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    #[Test]
    public function anEmptyInteractionRepositoryHasNoLastInteraction(): void
    {
        // When / Then
        static::assertNull(new InMemoryInteractionRepository()->last());
    }

    #[Test]
    public function itFindsAnInteractionByIdentifier(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();
        $repository->save($first);
        $repository->save($second);

        // When / Then
        static::assertSame($first, $repository->find($first->id));
        static::assertSame($second, $repository->find($second->id));
        static::assertNull($repository->find(Secrets::draw()));
    }

    #[Test]
    public function theLastInteractionSavedIsTheLast(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();

        // When
        $repository->save($first);
        $repository->save($second);
        $repository->save($first);

        // Then
        static::assertSame($second, $repository->last());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function anEmptyConsentRepositoryHasNoActiveConsent(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When / Then
        static::assertNull($repository->findActive($this->session->user, $this->client));
    }

    /**
     * The consent in force is the active one granted last, for this user and this client only.
     */
    #[Test]
    public function itFindsTheActiveConsentGrantedLast(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $older = $this->consent($alice, $this->client, '-2 days');
        $newer = $this->consent($alice, $this->client, '-1 day');
        $revoked = $this->consent($alice, $this->client, '+0 seconds');
        $revoked->revoke(Fixtures::now());
        foreach ([$newer, $older, $revoked] as $consent) {
            $repository->save($consent);
        }

        // When / Then
        static::assertSame($newer, $repository->findActive($alice, $this->client));
    }

    #[Test]
    public function theConsentOfAnotherUserOrClientIsNotFound(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $bob = Fixtures::user($alice->tenant, 'bob', 'bob-subject');
        $another = Clients::public($alice->tenant, 'another');
        $bobs = $this->consent($bob, $this->client, '+0 seconds');
        $repository->save($bobs);
        $repository->save($this->consent($alice, $another, '+0 seconds'));

        // When / Then
        static::assertSame($bobs, $repository->findActive($bob, $this->client));
        static::assertNull($repository->findActive($bob, $another));
    }

    #[Test]
    public function everyConsentSavedIsKept(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When
        foreach (['-2 days', '-1 day', '+0 seconds'] as $grantedAt) {
            $repository->save($this->consent($this->session->user, $this->client, $grantedAt));
        }

        // Then
        static::assertCount(3, $repository->all());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function betweenTwoConsentsGrantedAtTheSameInstantTheLastSavedWins(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $repository->save($this->consent($this->session->user, $this->client, '-1 day'));
        $tie = $this->consent($this->session->user, $this->client, '-1 day');

        // When
        $repository->save($tie);

        // Then
        static::assertSame($tie, $repository->findActive($this->session->user, $this->client));
    }

    /**
     * What the page of the account reads: one line per client, the most recently granted first, and
     * nothing of what was taken back.
     */
    #[Test]
    public function itListsWhatAUserHasInForce(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $another = Clients::public($alice->tenant, 'another');
        $older = $this->consent($alice, $another, '-2 days');
        $newer = $this->consent($alice, $this->client, '-1 day');
        $revoked = $this->consent($alice, Clients::public($alice->tenant, 'third'), '+0 seconds');
        $revoked->revoke(Fixtures::now());
        foreach ([$older, $newer, $revoked] as $consent) {
            $repository->save($consent);
        }
        $repository->save($this->consent(Fixtures::user($alice->tenant, 'bob', 'bob-subject'), $this->client, '+0 seconds'));

        // When / Then
        static::assertSame([$newer, $older], $repository->activeOf($alice));
    }

    #[Test]
    public function itRevokesTheGrantsAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = $this->code('mine');
        $elsewhere = Tokens::code('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now());
        $repository->save($mine);
        $repository->save($elsewhere);

        // When / Then
        static::assertSame([$mine], $repository->revokeByConsent($consent, Fixtures::now()));
    }

    #[Test]
    public function itFindsTheRefreshTokensAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = Tokens::refreshToken('mine', $this->client, $this->session, Fixtures::now());
        $repository->save($mine);
        $repository->save(Tokens::refreshToken('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now()));

        // When / Then
        static::assertSame([$mine], $repository->ofConsent($consent));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself descends from no user and from no consent.
     */
    #[Test]
    public function itRemovesTheAccessTokensAClientHoldsForAUser(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $consent = $this->consent($this->session->user, $this->client, '-1 day');
        $mine = Tokens::storedAccessToken('mine', $this->client, $this->session, Fixtures::now());
        $ofTheClientItself = Tokens::storedClientAccessToken('its own', $this->client, Fixtures::now());
        $repository->save($mine);
        $repository->save($ofTheClientItself);
        $repository->save(Tokens::storedAccessToken('elsewhere', Clients::public($this->session->tenant, 'another'), $this->session, Fixtures::now()));

        // When
        $removed = $repository->revokeByConsent($consent);

        // Then
        static::assertSame([$mine], $removed);
        static::assertNull($repository->find('mine'));
        static::assertNotNull($repository->find('its own'));
        static::assertNotNull($repository->find('elsewhere'));
    }

    #[Test]
    public function anEmptyCodeRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByCodeHash(DrawnSecret::digestOf('one')));
    }

    #[Test]
    public function itKeepsEachCodeOnceByHash(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');

        // When
        $repository->save($code);
        $repository->save($code);

        // Then
        static::assertSame([$code], $repository->all());
        static::assertSame(2, $repository->saves);
    }

    #[Test]
    public function itFindsACodeByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');
        $repository->save($code);

        // When / Then
        static::assertSame($code, $repository->findByCodeHash(DrawnSecret::digestOf('one')));
        static::assertNull($repository->findByCodeHash(DrawnSecret::digestOf('two')));
        static::assertNull($repository->findByCodeHash('one'), 'the lookup is by hash, never by value');
    }

    /**
     * RFC 6749 §4.1.2: the claim of a code is told to one caller only, the others read a replay.
     */
    #[Test]
    public function onlyTheFirstCallerConsumesACode(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');
        $repository->save($code);

        // When / Then
        static::assertTrue($repository->consume($code, Fixtures::now()));
        static::assertFalse($repository->consume($code, Fixtures::now()->modify('+1 second')));
        static::assertEquals(Fixtures::now(), $code->usedAt);
    }

    #[Test]
    public function anUnknownCodeIsNotConsumed(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();

        // When / Then
        static::assertFalse($repository->consume($this->code('one'), Fixtures::now()));
    }

    #[Test]
    public function itFindsAPushedRequestByTheHashOfItsReferenceNeverByItsValue(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();
        $requestUri = RequestUri::of(Secrets::draw());
        $repository->save($this->pushedRequest($requestUri));

        // When / Then
        static::assertNotNull($repository->findByRequestUriHash($requestUri->hash()));
        static::assertNull($repository->findByRequestUriHash(RequestUri::of(Secrets::draw())->hash()));
        static::assertNull($repository->findByRequestUriHash($requestUri->value), 'the lookup is by hash, never by value');
    }

    /**
     * RFC 9126 §4: the claim of a reference is told to one caller only, the others read a replay.
     */
    #[Test]
    public function onlyTheFirstCallerConsumesAPushedRequest(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();
        $request = $this->pushedRequest(RequestUri::of(Secrets::draw()));
        $repository->save($request);

        // When / Then
        static::assertTrue($repository->consume($request, Fixtures::now()));
        static::assertFalse($repository->consume($request, Fixtures::now()->modify('+1 second')));
        static::assertEquals(Fixtures::now(), $request->usedAt);
    }

    #[Test]
    public function anUnknownPushedRequestIsNotConsumed(): void
    {
        // Given
        $repository = new InMemoryPushedAuthorizationRecordRepository();

        // When / Then
        static::assertFalse($repository->consume($this->pushedRequest(RequestUri::of(Secrets::draw())), Fixtures::now()));
    }

    /**
     * Back-Channel Logout 1.0 §2.6: the clients of a session come back as a list, whatever the number of
     * grants each of them holds, because a caller iterates them and a gap would be a client kept twice.
     */
    #[Test]
    public function theClientsOfASessionComeBackAsAListOfEachClientOnce(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        foreach (['one', 'two'] as $value) {
            $code = $this->code($value);
            $code->consume(Fixtures::now());
            $repository->save($code);
        }

        // When
        $clients = $repository->ofSession($this->session->id);

        // Then
        static::assertSame([0], array_keys($clients));
        static::assertSame($this->client, $clients[0]);
    }

    #[Test]
    public function anEmptyRefreshTokenRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByTokenHash(DrawnSecret::digestOf('first')));
        static::assertSame([], $repository->findByFamily($family->id));
        static::assertSame([], $repository->findByAuthorizationCode(DrawnSecret::digestOf('first-code')));
        static::assertSame([], $repository->findBySession($this->session->id));
    }

    /**
     * Architecture §4.6: a token is found by its hash, never by its value.
     */
    #[Test]
    public function itFindsARefreshTokenByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $repository->save($first);

        // When / Then
        static::assertSame($first, $repository->findByTokenHash(DrawnSecret::digestOf('first')));
        static::assertNull($repository->findByTokenHash('first'), 'the lookup is by hash, never by value');
        static::assertNull($repository->findByTokenHash(DrawnSecret::digestOf('unknown')));
    }

    /**
     * Architecture §4.6: a family is found whole, whatever the state of its members.
     */
    #[Test]
    public function itFindsAFamilyWhole(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByFamily($family->id));
        static::assertSame([$other], $repository->findByFamily($other->family->id));
        static::assertSame([], $repository->findByFamily(Uuid::v7()));
    }

    /**
     * Architecture §4.6: the descendants of a code are the family.
     */
    #[Test]
    public function itFindsTheDescendantsOfACode(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByAuthorizationCode(DrawnSecret::digestOf('first-code')));
        static::assertSame([$other], $repository->findByAuthorizationCode(DrawnSecret::digestOf('other-code')));
        static::assertSame([], $repository->findByAuthorizationCode(DrawnSecret::digestOf('unknown')));
    }

    /**
     * Architecture §4.9: the tokens of a session are found whole, rotated and revoked ones included.
     */
    #[Test]
    public function itFindsEveryTokenOfASession(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $lineage = $this->lineage(Tokens::family(Fixtures::now(), 'first-code'));
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        $elsewhere = Tokens::refreshToken(
            'elsewhere',
            $this->client,
            Fixtures::session(Fixtures::user($this->session->tenant, 'bob', 'bob-subject')),
            Fixtures::now(),
        );
        foreach ([...$lineage, $other, $elsewhere] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame([...$lineage, $other], $repository->findBySession($this->session->id));
        static::assertSame([$elsewhere], $repository->findBySession($elsewhere->session->id));
        static::assertSame([], $repository->findBySession(Uuid::v7()));
    }

    #[Test]
    public function itKeepsEachRefreshTokenOnce(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now());

        // When
        foreach ([$first, $second, $first] as $token) {
            $repository->save($token);
        }

        // Then
        static::assertSame([$first, $second], $repository->all());
        static::assertSame(3, $repository->saves);
    }

    /**
     * Architecture §4.6: a token is kept under the digest of a value the store never sees, and found by
     * that value.
     */
    #[Test]
    public function itKeepsAnAccessTokenAndFindsItByItsValue(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $authorization = UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code(
            'the-code',
            $this->client,
            $this->session,
            Fixtures::now(),
            ['openid', 'email'],
        ));

        $value = Secrets::draw();

        // When
        $repository->save($authorization->storedUnder(DrawnSecret::digestOf($value), Fixtures::now(), Fixtures::now()->modify('+10 minutes')));

        // Then
        $record = $repository->find($value) ?? static::fail('The token was kept.');
        static::assertInstanceOf(StoredUserAccessToken::class, $record);
        static::assertSame(DrawnSecret::digestOf($value), $record->tokenHash);
        static::assertSame($this->client, $record->client);
        static::assertSame($this->session, $record->session);
        static::assertTrue($authorization->grantId->equals($record->grantId));
        static::assertSame(['openid', 'email'], $record->scopes->values());
        static::assertEquals(Fixtures::now(), $record->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $record->expiresAt);
        static::assertNull($repository->find(DrawnSecret::digestOf($value)), 'the hash is not the value');
    }

    #[Test]
    public function anEmptyAccessTokenRepositoryFindsNothing(): void
    {
        // When / Then
        static::assertNull(new InMemoryAccessTokenRepository()->find('unknown'));
    }

    /**
     * RFC 7009: a revoked token is gone; the others stay.
     */
    #[Test]
    public function itRevokesOneAccessToken(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $revoked = Tokens::storedAccessToken('revoked', $this->client, $this->session, Fixtures::now());
        $kept = Tokens::storedAccessToken('kept', $this->client, $this->session, Fixtures::now());
        $repository->save($revoked);
        $repository->save($kept);

        // When
        $repository->revoke($revoked);

        // Then
        static::assertNull($repository->find('revoked'));
        static::assertSame([$kept], $repository->all());
    }

    /**
     * RFC 6749 §4.1.2: the tokens of a grant go together, and are told; one of another grant stays.
     */
    #[Test]
    public function itRevokesTheAccessTokensOfAGrant(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $grant = Uuid::v7();
        $first = Tokens::storedAccessToken('first', $this->client, $this->session, Fixtures::now(), $grant);
        $second = Tokens::storedAccessToken('second', $this->client, $this->session, Fixtures::now(), $grant);
        $other = Tokens::storedAccessToken('other', $this->client, $this->session, Fixtures::now());
        foreach ([$first, $second, $other] as $token) {
            $repository->save($token);
        }

        // When
        $revoked = $repository->revokeByGrant($grant);

        // Then
        static::assertSame([$first, $second], $revoked);
        static::assertSame([$other], $repository->all());
        static::assertSame([], $repository->revokeByGrant($grant), 'nothing left');
    }

    /**
     * Architecture §4.6, RFC 6749 §4.4: the record kept for an authorization is the record of its kind, and
     * the store is handed it by the authorization rather than recognising which kind it was given.
     */
    #[Test]
    public function itKeepsAnAccessTokenNobodySignedInForAsTheRecordOfItsKind(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $service = Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $authorization = new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $service,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );

        $value = Secrets::draw();

        // When
        $repository->save($authorization->storedUnder(DrawnSecret::digestOf($value), Fixtures::now(), Fixtures::now()->modify('+10 minutes')));

        // Then
        $record = $repository->find($value) ?? static::fail('The token was kept.');
        static::assertInstanceOf(StoredClientAccessToken::class, $record);
        static::assertSame($service, $record->client);
        static::assertTrue($authorization->grantId->equals($record->grantId));
        static::assertSame([Clients::CALENDAR], $record->resources?->values());
    }

    /**
     * Architecture §4.9, RFC 6749 §4.4: a logout revokes the tokens of the session that ended, and a token
     * nobody signed in for has no session to have ended.
     */
    #[Test]
    public function aLogoutLeavesTheAccessTokensNobodySignedInFor(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $ofTheSession = Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now());
        $ofTheService = Tokens::storedClientAccessToken(
            'batch',
            Clients::service($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET)),
            Fixtures::now(),
        );
        $repository->save($ofTheSession);
        $repository->save($ofTheService);

        // When
        $revoked = $repository->revokeBySession($this->session->id);

        // Then
        static::assertSame([$ofTheSession], $revoked);
        static::assertSame([$ofTheService], $repository->all());
    }

    /**
     * Architecture §4.9: the tokens of a session go together; one of another session stays.
     */
    #[Test]
    public function itRevokesTheAccessTokensOfASession(): void
    {
        // Given
        $repository = new InMemoryAccessTokenRepository();
        $here = Tokens::storedAccessToken('here', $this->client, $this->session, Fixtures::now());
        $elsewhere = Tokens::storedAccessToken(
            'elsewhere',
            $this->client,
            Fixtures::session(Fixtures::user($this->session->tenant, 'bob', 'bob-subject')),
            Fixtures::now(),
        );
        $repository->save($here);
        $repository->save($elsewhere);

        // When
        $revoked = $repository->revokeBySession($this->session->id);

        // Then
        static::assertSame([$here], $revoked);
        static::assertSame([$elsewhere], $repository->all());
    }

    private function interaction(): Interaction
    {
        return new Interaction(
            Secrets::draw(),
            $this->client->tenant,
            Requests::authorization($this->client),
            null,
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );
    }

    private function consent(User $user, Client $client, string $grantedAt): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, new Scopes([Scope::openid()]), Fixtures::now()->modify($grantedAt));
    }

    private function pushedRequest(RequestUri $requestUri): PushedAuthorizationRecord
    {
        return new PushedAuthorizationRecord(
            $requestUri->hash(),
            $this->client,
            [
                'scope' => 'openid',
            ],
            Fixtures::now(),
            Fixtures::now()->modify('+60 seconds'),
        );
    }

    private function code(string $value): AuthorizationCode
    {
        return new AuthorizationCode(
            DrawnSecret::digestOf($value),
            Uuid::v7(),
            $this->client,
            $this->session,
            $this->client->registration->redirectUris[0],
            new Scopes([Scope::openid()]),
            null,
            null,
            null,
            new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()),
            null,
            null,
            new AuthenticationSnapshot(Fixtures::now(), ['pwd'], '1'),
            Fixtures::now(),
            Fixtures::now()->modify('+60 seconds'),
        );
    }

    /**
     * A first token rotated into a second, then a revoked one, in the family given.
     *
     * @return list<RefreshToken>
     */
    private function lineage(RefreshTokenFamily $family): array
    {
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now(), $family);
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now()->modify('+1 day'), $family);
        $first->rotate(Fixtures::now()->modify('+1 day'));
        $revoked = Tokens::refreshToken('revoked', $this->client, $this->session, Fixtures::now()->modify('+2 days'), $family);
        $revoked->revoke(Fixtures::now()->modify('+2 days'));

        return [$first, $second, $revoked];
    }
}
