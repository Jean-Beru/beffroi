<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Ciba;

use DateTimeImmutable;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Identity\User;
use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Ciba\ApprovalAuthenticationRequirement;
use Heidi\Oidc\Application\Ciba\BackchannelApproval;
use Heidi\Oidc\Application\Consent\ConsentGranting;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Ciba\BindingMessage;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeSecretSealer;
use Heidi\Oidc\Tests\Fixture\Logins;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §10.1, §11, BCP 10027 §5.2: what the page where a user answers asks of the provider. What is
 * waiting is found by who is signed in, and a request of somebody else is not in that list and is not
 * answerable.
 */
final class BackchannelApprovalTest extends TestCase
{
    private const string AUTH_REQUEST_ID = 'the-auth-req-id';

    private Tenant $tenant;

    private Client $client;

    private User $alice;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryBackchannelAuthenticationRecordRepository $records;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private InMemoryCredentialRepository $credentials;

    private BackchannelApproval $approval;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::backchannel($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->alice = Fixtures::user($this->tenant);
        $this->session = Fixtures::session($this->alice, $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->records = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->events = new RecordingEventDispatcher();
        $this->credentials = new InMemoryCredentialRepository();
        $this->approval = new BackchannelApproval(
            $this->records,
            new ConsentGranting(new InMemoryConsentRepository(), new SymfonyUuidGenerator(), $this->events),
            new ApprovalAuthenticationRequirement(Logins::passwordAndPasskey(), $this->credentials),
            new FakeSecretSealer(),
            $this->events,
            $this->clock,
        );
    }

    /**
     * §10.1: what is waiting for this user, and nothing that is waiting for somebody else.
     */
    #[Test]
    public function itShowsTheRequestsMadeForThatUser(): void
    {
        // Given
        $this->records->save($this->record());
        $this->records->save($this->record('for-bob', Fixtures::user($this->tenant, 'bob', 'bob-subject')));

        // When
        $waiting = $this->approval->awaitingAnAnswerBy($this->alice);

        // Then
        static::assertCount(1, $waiting);
        static::assertSame(DrawnSecret::digestOf(self::AUTH_REQUEST_ID), $waiting[0]->authRequestIdHash);
    }

    /**
     * A request that was answered, that expired or that was spent is waiting for nobody.
     */
    #[Test]
    public function aRequestThatIsNoLongerWaitingIsNotShown(): void
    {
        // Given
        $answered = $this->record('answered');
        $answered->deny($this->clock->now());
        $this->records->save($answered);
        $spent = $this->record('spent');
        $spent->consume($this->clock->now());
        $this->records->save($spent);
        $this->records->save($this->record('expired', expiresAt: $this->clock->now()->modify('+1 second')));
        $this->clock->modify('+2 seconds');

        // When
        $waiting = $this->approval->awaitingAnAnswerBy($this->alice);

        // Then
        static::assertSame([], $waiting);
    }

    /**
     * A handle is looked for among the requests that user may answer, so a request of somebody else is
     * named by nothing.
     */
    #[Test]
    public function aHandleNamesOnlyARequestThatUserMayAnswer(): void
    {
        // Given
        $this->records->save($this->record('for-bob', Fixtures::user($this->tenant, 'bob', 'bob-subject')));

        // When
        $record = $this->approval->awaitingAnAnswerFrom($this->alice, DrawnSecret::digestOf('for-bob'));

        // Then
        static::assertNull($record);
    }

    /**
     * §10.1: approving is granting an authorization of the ordinary kind, with the consent recorded where
     * a consent is recorded and the session frozen on the record.
     */
    #[Test]
    public function anApprovalRecordsAConsentAndFreezesTheSession(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertTrue($record->isApproved());
        static::assertSame($this->session, $record->session);
        static::assertNotNull($record->authentication);
        static::assertInstanceOf(ConsentGranted::class, $this->events->events[0] ?? null);
    }

    /**
     * §7.1: only the user the request named may answer it.
     */
    #[Test]
    public function aSessionOfSomebodyElseApprovesNothing(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);
        $bob = Fixtures::session(Fixtures::user($this->tenant, 'bob', 'bob-subject'), $this->clock->now());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->approval->approve($record, $bob, $this->context);
    }

    /**
     * §11: a refusal is an answer and ends the request.
     */
    #[Test]
    public function aRefusalEndsTheRequest(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->deny($record, $this->context);

        // Then
        static::assertTrue($record->isDenied());
        static::assertSame([], $this->approval->awaitingAnAnswerBy($this->alice));
    }

    /**
     * §10.1: a client that only polls is told nothing; it finds the answer at the token endpoint.
     */
    #[Test]
    public function aPollingClientIsNotCalledBack(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertSame(
            [],
            array_values(array_filter(
                $this->events->events,
                static fn (object $event): bool => $event instanceof BackchannelRequestAnswered,
            )),
        );
    }

    /**
     * §10.2: a client that registered to be called back is told that the request is over, with the
     * identifier it was handed and the token it sent, both read back out of their envelopes.
     */
    #[Test]
    public function aPingedClientIsToldTheRequestIsOver(): void
    {
        // Given
        $record = $this->pingedRecord();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        $answered = $this->answeredEvent();
        static::assertSame('payment-terminal', $answered->clientId);
        static::assertSame(Clients::NOTIFICATION_ENDPOINT, $answered->notificationEndpoint->value);
        static::assertSame(self::AUTH_REQUEST_ID, $answered->authRequestId);
        static::assertSame('the-notification-token', $answered->notificationToken);
    }

    /**
     * §10.2: the client is told that the request is over whichever way it was answered; what it was
     * answered, it reads at the token endpoint.
     */
    #[Test]
    public function aPingedClientIsAlsoToldOfARefusal(): void
    {
        // Given
        $record = $this->pingedRecord();
        $this->records->save($record);

        // When
        $this->approval->deny($record, $this->context);

        // Then
        static::assertSame(self::AUTH_REQUEST_ID, $this->answeredEvent()->authRequestId);
    }

    /**
     * §7.1: a session that may not answer a request owes it nothing; what is asked of what it proves is
     * asked of the user the request named, and this one is refused for who it is.
     */
    #[Test]
    public function aSessionOfSomebodyElseIsRefusedForWhoItIsAndNotForWhatItProves(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->credentials->save(Fixtures::passkey($bob));
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is approved by the user it named, with a session of its own tenant.');

        // When
        $this->approval->approve($record, Fixtures::session($bob, $this->clock->now()), $this->context);
    }

    /**
     * §7.1, decision 0010: the client asked for a class this session does not prove and a passkey of this
     * user would, so one more proof is owed before the approval may be recorded.
     */
    #[Test]
    public function aSessionThatProvesNoRequestedClassOwesOneMoreProof(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // When
        $stepUp = $this->approval->stepUpFor($record, $this->session) ?? static::fail('The session owes no proof.');

        // Then
        static::assertSame(['phr'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes));
        static::assertSame(['passkey'], $stepUp->kinds());
    }

    /**
     * §7.1: a session that owes one more proof approves nothing; the page reads it before it offers the
     * answer.
     */
    #[Test]
    public function anApprovalBySuchASessionIsRefused(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is approved by a session that proves what it asked for; the page that answers it reads stepUpFor() first.');

        // When
        $this->approval->approve($record, $this->session, $this->context);
    }

    /**
     * OIDC Core §5.5.1.1: the demand is a request and not a condition, so a class no credential of this
     * user could ever reach is asked of nobody and the request is answered all the same.
     */
    #[Test]
    public function aClassNoCredentialOfTheUserCouldReachOwesNothing(): void
    {
        // Given
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertTrue($record->isApproved());
        static::assertSame('1', $record->authentication?->contextClass);
    }

    /**
     * OIDC Core §2, §5.5.1.1: the tokens name the requested class the session satisfies, which may be
     * below the strongest it satisfies, and never the one the request asked for.
     */
    #[Test]
    public function theTokensNameTheRequestedClassTheSessionSatisfies(): void
    {
        // Given
        $record = $this->record(acrValues: ['phr', '1']);
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertSame('1', $record->authentication?->contextClass);
    }

    private function aliceHoldsAPasskey(): PasskeyCredential
    {
        $passkey = Fixtures::passkey($this->alice);
        $this->credentials->save($passkey);

        return $passkey;
    }

    private function answeredEvent(): BackchannelRequestAnswered
    {
        foreach ($this->events->events as $event) {
            if ($event instanceof BackchannelRequestAnswered) {
                return $event;
            }
        }

        static::fail('The client was never told the request was over.');
    }

    private function pingedRecord(): BackchannelAuthenticationRecord
    {
        $sealer = new FakeSecretSealer();
        $client = Clients::pinged($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));

        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf(self::AUTH_REQUEST_ID),
            Uuid::v7(),
            $client,
            $this->alice,
            new Scopes([Scope::openid()]),
            null,
            new BindingMessage('Payment of 42 euros'),
            [],
            $sealer->seal($this->tenant, self::AUTH_REQUEST_ID),
            $sealer->seal($this->tenant, 'the-notification-token'),
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }

    /**
     * @param list<string> $acrValues
     */
    private function record(
        string $authRequestId = self::AUTH_REQUEST_ID,
        ?User $user = null,
        ?DateTimeImmutable $expiresAt = null,
        array $acrValues = [],
    ): BackchannelAuthenticationRecord {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf($authRequestId),
            Uuid::v7(),
            $this->client,
            $user ?? $this->alice,
            new Scopes([Scope::openid()]),
            null,
            null,
            $acrValues,
            null,
            null,
            $this->context,
            $this->clock->now(),
            $expiresAt ?? $this->clock->now()->modify('+300 seconds'),
        );
    }
}
