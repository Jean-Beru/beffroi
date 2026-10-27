<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Ciba;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §7, §10.1, §11: the record waits for the user it named, who answers it once, and for the
 * client, which spends it once and is told to slow down when it asks faster than it was told to.
 */
final class BackchannelAuthenticationRecordTest extends TestCase
{
    private Client $client;

    private User $user;

    private AuthenticationSession $session;

    private DateTimeImmutable $issuedAt;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::backchannel($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->user = Fixtures::user($tenant);
        $this->session = Fixtures::session($this->user);
        $this->issuedAt = new DateTimeImmutable('2026-09-26T09:00:00+00:00');
    }

    #[Test]
    public function itIsBoundToItsClientAndToTheTenantOfThatClient(): void
    {
        // When
        $record = $this->record();

        // Then
        static::assertSame('payment-terminal', $record->clientId);
        static::assertSame($this->client->tenant, $record->tenant);
        static::assertTrue($record->belongsTo($this->client));
        static::assertFalse($record->isAnswered());
        static::assertFalse($record->isUsed());
    }

    /**
     * CIBA Core §7.3: the lifetime the client is told is the one the record has, never a longer one.
     */
    #[Test]
    public function theLifetimeItAnnouncesIsTheOneItHas(): void
    {
        // Given
        $record = $this->record();

        // When / Then
        static::assertSame(300, $record->expiresIn($this->issuedAt));
        static::assertSame(1, $record->expiresIn($this->issuedAt->modify('+300 seconds')), 'never zero, never negative');
    }

    /**
     * CIBA Core §7.1: the request named a user, and that user is the only one who may answer it.
     */
    #[Test]
    public function onlyTheUserItNamedMayAnswerIt(): void
    {
        // Given
        $record = $this->record();

        // When / Then
        static::assertTrue($record->mayBeAnsweredBy($this->user));
        static::assertFalse($record->mayBeAnsweredBy(Fixtures::user($this->client->tenant, 'bob', 'bob-subject')));
    }

    /**
     * A request whose hint named nobody is answerable by nobody, and stays until it expires
     * (decision 0006).
     */
    #[Test]
    public function aRequestThatNamedNobodyIsAnsweredByNobody(): void
    {
        // Given
        $record = $this->record(named: false);

        // When / Then
        static::assertFalse($record->mayBeAnsweredBy($this->user));
        static::assertNull($record->user);
    }

    /**
     * CIBA Core §10.1: what the user approved with is frozen on the record, so that the tokens the client
     * comes for descend from the approval.
     */
    #[Test]
    public function anApprovalFreezesTheSessionAndWhatItHadProven(): void
    {
        // Given
        $record = $this->record();
        $snapshot = AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass());

        // When
        $record->approve($this->session, $snapshot, $this->issuedAt);

        // Then
        static::assertTrue($record->isApproved());
        static::assertTrue($record->isAnswered());
        static::assertSame($this->session, $record->session);
        static::assertSame($snapshot, $record->authentication);
        static::assertSame($this->issuedAt, $record->approvedAt);
    }

    /**
     * CIBA Core §7.1: somebody else's session approves nothing, whatever it proves.
     */
    #[Test]
    public function aSessionOfAnotherUserApprovesNothing(): void
    {
        // Given
        $record = $this->record();
        $other = Fixtures::session(Fixtures::user($this->client->tenant, 'bob', 'bob-subject'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is approved by the user it named, with a session of its own tenant.');

        // When
        $record->approve($other, AuthenticationSnapshot::ofSession($other, $other->authenticationContextClass()), $this->issuedAt);
    }

    /**
     * CIBA Core §11: a refusal is an answer and ends the request.
     */
    #[Test]
    public function aRefusalIsAnAnswer(): void
    {
        // Given
        $record = $this->record();

        // When
        $record->deny($this->issuedAt);

        // Then
        static::assertTrue($record->isDenied());
        static::assertTrue($record->isAnswered());
        static::assertFalse($record->isApproved());
    }

    /**
     * Nobody is asked twice about the same request; whoever answers reads isAnswered() first.
     */
    #[Test]
    public function aRequestIsAnsweredOnce(): void
    {
        // Given
        $record = $this->record();
        $record->deny($this->issuedAt);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is answered once; the page that answers it reads isAnswered() first.');

        // When
        $record->approve($this->session, AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()), $this->issuedAt);
    }

    /**
     * CIBA Core §11: a client polling faster than the interval it was given is told so, and the interval
     * grows by five seconds for that request and every one after it.
     */
    #[Test]
    public function pollingFasterThanTheIntervalGrowsIt(): void
    {
        // Given
        $record = $this->record();

        // When / Then
        static::assertFalse($record->polledTooSoon($this->issuedAt), 'the first poll is never too soon');
        static::assertTrue($record->polledTooSoon($this->issuedAt->modify('+1 second')));
        static::assertSame(10, $record->interval);
        static::assertTrue($record->polledTooSoon($this->issuedAt->modify('+8 seconds')), 'the interval it grew to is the one that counts');
        static::assertSame(15, $record->interval);
    }

    /**
     * CIBA Core §11: every poll is recorded, the refused ones included; asking again does not buy a
     * faster answer.
     */
    #[Test]
    public function aPollThatWasRefusedIsStillAPoll(): void
    {
        // Given
        $record = $this->record();
        $record->polledTooSoon($this->issuedAt);
        $record->polledTooSoon($this->issuedAt->modify('+1 second'));

        // When / Then
        static::assertEquals($this->issuedAt->modify('+1 second'), $record->lastPolledAt);
    }

    /**
     * §10.1: of any number of requests presenting the same identifier at once, exactly one is served.
     */
    #[Test]
    public function anIdentifierIsSpentOnce(): void
    {
        // Given
        $record = $this->record();
        $record->consume($this->issuedAt);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is consumed once; the backchannel authentication grant checks isUsed() first.');

        // When
        $record->consume($this->issuedAt);
    }

    /**
     * The identifier is kept as its digest, as every value this provider hands out is.
     */
    #[Test]
    public function itIsStoredAsTheDigestOfTheIdentifierItAnsweredWith(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is stored as the hex SHA-256 of its auth_req_id.');

        // When
        new BackchannelAuthenticationRecord(
            'not-a-digest',
            Uuid::v7(),
            $this->client,
            $this->user,
            new Scopes([Scope::openid()]),
            null,
            null,
            [],
            null,
            null,
            Fixtures::context(),
            $this->issuedAt,
            $this->issuedAt->modify('+300 seconds'),
        );
    }

    /**
     * A record of a user of another tenant is not a record at all.
     */
    #[Test]
    public function theUserItNamesBelongsToTheTenantOfItsClient(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request names a user of the tenant of its client.');

        // When
        $this->record(user: Fixtures::user(Fixtures::tenant('other', 'https://id.other.example')));
    }

    /**
     * A request that expires before it was asked for is no request.
     */
    #[Test]
    public function itExpiresAfterItWasAskedFor(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request expires after it was asked for.');

        // When
        $this->record(expiresAt: $this->issuedAt);
    }

    /**
     * CIBA Core §7.3: an interval of no seconds is not an interval.
     */
    #[Test]
    public function itAnnouncesAnIntervalOfAtLeastOneSecond(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request announces a polling interval of at least one second (CIBA Core section 7.3).');

        // When
        $this->record(interval: 0);
    }

    /**
     * CIBA Core §11: an interval a client is asked to respect is one it can respect.
     */
    #[Test]
    public function itAnnouncesAnIntervalOfAtMostItsBound(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request announces a polling interval of at most 30 seconds, a client respecting it (CIBA Core section 11); 31 given.');

        // When
        $this->record(interval: BackchannelAuthenticationRecord::MAX_INTERVAL + 1);
    }

    /**
     * CIBA Core §7.3, §11: a request is made with an interval of a second at least and of the bound at most,
     * both ends included.
     */
    #[Test]
    #[DataProvider('provideIntervalsARequestIsMadeWith')]
    public function itIsMadeWithAnIntervalFromOneSecondToItsBound(int $interval): void
    {
        // When
        $record = $this->record(interval: $interval);

        // Then
        static::assertSame($interval, $record->interval);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIntervalsARequestIsMadeWith(): iterable
    {
        yield 'a second' => [1];
        yield 'the bound' => [BackchannelAuthenticationRecord::MAX_INTERVAL];
    }

    /**
     * The message the user is shown is the one the client sent, and the resolved client is held by the
     * record itself (ResolvesItsClientInterface).
     */
    #[Test]
    public function itCarriesTheMessageItsUserWillBeShown(): void
    {
        // Given
        $message = new BindingMessage('Payment of 42 euros');

        // When
        $record = $this->record(bindingMessage: $message);

        // Then
        static::assertSame($message, $record->bindingMessage);
        static::assertSame($record, $record->clientHolder());
    }

    /**
     * @param list<string> $acrValues
     */
    private function record(
        ?User $user = null,
        bool $named = true,
        ?BindingMessage $bindingMessage = null,
        ?DateTimeImmutable $expiresAt = null,
        int $interval = 5,
        array $acrValues = [],
    ): BackchannelAuthenticationRecord {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf('the-auth-req-id'),
            Uuid::v7(),
            $this->client,
            $named ? $user ?? $this->user : null,
            new Scopes([Scope::openid()]),
            null,
            $bindingMessage,
            $acrValues,
            null,
            null,
            Fixtures::context(),
            $this->issuedAt,
            $expiresAt ?? $this->issuedAt->modify('+300 seconds'),
            $interval,
        );
    }
}
