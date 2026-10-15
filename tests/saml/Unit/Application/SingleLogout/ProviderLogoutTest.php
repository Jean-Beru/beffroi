<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleLogout;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainEnded;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\LogoutHop;
use Beffroi\Saml\Domain\SingleLogout\LogoutProgress;
use Beffroi\Saml\Domain\SingleLogout\LogoutRequester;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutNotice;
use Beffroi\Saml\Domain\SingleLogout\SignOutStatus;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\InMemoryLogoutChains;
use Beffroi\Saml\Tests\Fixture\InMemorySessionParticipations;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutNotifier;
use Beffroi\Saml\Tests\Fixture\RecordingSignOutResponder;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.6, S-29 to S-34: every service provider of the sessions a browser ended told in turn, the
 * chain kept by the provider and played once, and where it ends.
 */
final class ProviderLogoutTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example' . FixedEndpoints::METADATA;

    private const string FIRST = 'https://first.example.org/saml';

    private const string SECOND = 'https://second.example.org/saml';

    private const string REQUESTER = 'https://asked.example.org/saml';

    private const string CONTINUE_TO = 'https://demo.example/?state=x';

    private Tenant $tenant;

    private MockClock $clock;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemorySessionParticipations $participations;

    private InMemoryLogoutChains $chains;

    private RecordingSignOutResponder $responder;

    private RecordingSignOutNotifier $notifier;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->participations = new InMemorySessionParticipations();
        $this->chains = new InMemoryLogoutChains();
        $this->responder = new RecordingSignOutResponder();
        $this->notifier = new RecordingSignOutNotifier();
        $this->session = $this->sessionSignedInAt([self::FIRST, self::REQUESTER, self::SECOND]);
    }

    /**
     * S-30, section 6.6 step 1: the service providers of each session, session by session, each in the order of its
     * first sign-on, the one that asked left out.
     */
    #[Test]
    public function theServiceProvidersOfEachSessionAreLeftToTellButTheOneThatAsked(): void
    {
        // Given
        $other = $this->sessionSignedInAt([self::SECOND]);

        // When
        $this->logout()->begin($this->tenant, [$this->session, $other], self::requester(), null);

        // Then
        static::assertEquals(
            [
                new LogoutHop($this->session->id, self::FIRST),
                new LogoutHop($this->session->id, self::SECOND),
                new LogoutHop($other->id, self::SECOND),
            ],
            $this->chains->all()[0]->progress->hops,
        );
    }

    /**
     * Section 6.6 step 1: nothing to tell and nobody to answer ends at once where the starter said, nothing written.
     */
    #[Test]
    public function nothingToTellEndsAtOnce(): void
    {
        // Given
        $alone = $this->sessionSignedInAt([]);

        // When
        $begun = $this->logout()->begin($this->tenant, [$alone], null, self::CONTINUE_TO);

        // Then
        static::assertEquals([new LogoutChainEnded(self::CONTINUE_TO), []], [$begun, $this->chains->all()]);
    }

    /**
     * S-32, section 6.6 step 1: the chain is written under the SHA-256 of a reference of 32 bytes in base64url,
     * waiting for no answer, open ten minutes, for the sessions ended.
     */
    #[Test]
    public function theChainIsWrittenUnderTheDigestOfItsReference(): void
    {
        // When
        $begun = $this->logout()->begin($this->tenant, [$this->session], null, self::CONTINUE_TO);

        // Then
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        $chain = $this->chains->all()[0];
        static::assertEquals(
            [43, LogoutChain::digestOf($begun->reference), null, Fixtures::now()->modify('+600 seconds'), [$this->session], [$this->session->id]],
            [strlen($begun->reference), $chain->reference, $chain->awaitingRequest, $chain->expiresAt, $begun->sessions, $chain->progress->sessions],
        );
    }

    /**
     * S-30, S-31, section 6.6 step 3: the first service provider is sent a notice naming it, the persistent NameID of
     * the user of the session at it, the ID of the session and the instant of the clock, by the identity provider of
     * the tenant; what carries it is what the browser is given.
     */
    #[Test]
    public function theFirstServiceProviderIsTold(): void
    {
        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertEquals(
            [
                [new SignOutNotice(
                    self::IDENTITY_PROVIDER,
                    self::FIRST,
                    PersistentNameId::derive(self::FIRST, $this->session->user->subject, FixedSalt::SALT)->value,
                    $this->session->id->toRfc4122(),
                    Fixtures::now(),
                )],
                new RedirectedMessage(self::FIRST . '/slo?SAMLRequest=told'),
            ],
            [$this->notifier->notices, $step],
        );
    }

    /**
     * S-32, section 6.6 step 3: the chain is written again under its reference, waiting for the answer of the request
     * sent, from the service provider it went to, open ten minutes from now.
     */
    #[Test]
    public function theChainWaitsForTheAnswerOfTheRequestSent(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->clock->modify('+30 seconds');

        // When
        $this->resumed($begun);

        // Then
        $chain = $this->chains->all()[0];
        static::assertSame(
            [RecordingSignOutNotifier::idOf(1), self::FIRST, [self::SECOND], Fixtures::now()->modify('+630 seconds')->getTimestamp()],
            [
                $chain->awaitingRequest,
                $chain->progress->awaitingFrom,
                array_map(static fn (LogoutHop $hop): string => $hop->serviceProvider, $chain->progress->hops),
                $chain->expiresAt->getTimestamp(),
            ],
        );
    }

    /**
     * S-32, section 6.6 step 2: a reference resumed once is not resumed again.
     */
    #[Test]
    public function aReferenceIsResumedOnce(): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        $this->resumed($begun);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->resumed($begun);
    }

    /**
     * S-32, section 6.6 step 2: a reference nobody wrote, and the reference of a chain past its ten minutes, resume
     * nothing.
     */
    #[Test]
    #[DataProvider('provideReferencesThatResumeNothing')]
    public function aReferenceThatHoldsNoOpenChainIsRefused(string $case): void
    {
        // Given
        $begun = $this->logout()->begin($this->tenant, [$this->session], self::requester(), null);
        static::assertInstanceOf(LogoutChainStarted::class, $begun);
        $reference = $case === 'nobody wrote' ? 'a-reference-nobody-wrote' : $begun->reference;
        $this->clock->modify($case === 'past its ten minutes' ? '+600 seconds' : '+599 seconds');

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->logout()->resume($this->tenant, $reference);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideReferencesThatResumeNothing(): iterable
    {
        yield 'a reference nobody wrote' => ['nobody wrote'];
        yield 'a chain past its ten minutes' => ['past its ten minutes'];
    }

    /**
     * S-32: a chain that waits for the answer of a service provider is not resumed by its reference, which would skip
     * that answer.
     */
    #[Test]
    public function aChainWaitingForAnAnswerIsNotResumedByItsReference(): void
    {
        // Given
        $this->chains->save(
            new LogoutChain(LogoutChain::digestOf('reference'), $this->tenant, '_request-1', self::progress(), Fixtures::now()->modify('+600 seconds')),
        );

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('No chain of logout waits to be resumed under this reference (spec/saml.md S-32).');

        // When
        $this->logout()->resume($this->tenant, 'reference');
    }

    /**
     * S-30, section 6.6 step 3: a service provider the notifier cannot tell is passed over, and the next one told.
     */
    #[Test]
    public function aServiceProviderThatCannotBeToldIsPassedOver(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier([self::FIRST]);

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // Then
        static::assertEquals(
            [new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), true],
            [$step, $this->chains->all()[0]->progress->partial],
        );
    }

    /**
     * S-30, section 6.6 step 3: a session no longer stored is passed over: no NameID can be computed for it.
     */
    #[Test]
    public function aSessionNoLongerStoredIsPassedOver(): void
    {
        // Given
        $gone = Fixtures::session(Fixtures::user($this->tenant));
        $this->participations->record(new SessionParticipation(Uuid::v7(), $this->tenant, $gone, self::SECOND, Fixtures::now()));

        // When
        $step = $this->resumed($this->logout()->begin($this->tenant, [$gone], self::requester(), null));

        // Then
        static::assertEquals(
            [[], SignOutStatus::PartialLogout, new RedirectedMessage(self::REQUESTER . '/slo?SAMLResponse=answered')],
            [$this->notifier->notices, $this->responder->response?->status, $step],
        );
    }

    /**
     * S-33, section 6.6 step 4: the answer of the service provider awaited moves the chain on to the next one.
     */
    #[Test]
    public function anAnswerMovesTheChainOnToTheNextServiceProvider(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // When
        $step = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true));

        // Then
        static::assertEquals(new RedirectedMessage(self::SECOND . '/slo?SAMLRequest=told'), $step);
    }

    /**
     * S-32: a chain another request took first is not played again from an answer.
     */
    #[Test]
    public function anAnswerToAChainAnotherRequestTookIsRefused(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));
        $chain = $this->chains->all()[0];
        $this->logout()->answered($this->tenant, new SignOutAnswer($chain, true));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The chain of logout was played by another request (spec/saml.md S-32).');

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($chain, true));
    }

    /**
     * S-34, section 6.6 step 5: the last answer ends a chain that answers nobody where its starter said.
     */
    #[Test]
    public function theLastAnswerEndsTheChainWhereItsStarterSaid(): void
    {
        // Given
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], null, self::CONTINUE_TO));
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true));
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true));

        // When
        $step = $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true));

        // Then
        static::assertEquals([new LogoutChainEnded(self::CONTINUE_TO), []], [$step, $this->chains->all()]);
    }

    /**
     * S-34, Core §3.7.3.2: the service provider that asked is answered at the end, Success when every other one
     * answered Success, PartialLogout when one did not, or was passed over.
     */
    #[Test]
    #[DataProvider('provideOutcomes')]
    public function theServiceProviderThatAskedIsAnsweredAtTheEnd(bool $firstSucceeds, bool $secondReachable, SignOutStatus $expected): void
    {
        // Given
        if (! $secondReachable) {
            $this->notifier = new RecordingSignOutNotifier([self::SECOND]);
        }
        $this->resumed($this->logout()->begin($this->tenant, [$this->session], self::requester(), null));

        // When
        $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], $firstSucceeds));
        if ($secondReachable) {
            $this->logout()->answered($this->tenant, new SignOutAnswer($this->chains->all()[0], true));
        }

        // Then
        static::assertEquals(
            [self::requester(), $expected, self::IDENTITY_PROVIDER, Fixtures::now()],
            [
                $this->responder->response?->requester,
                $this->responder->response?->status,
                $this->responder->response?->identityProvider,
                $this->responder->response?->issuedAt,
            ],
        );
    }

    /**
     * @return iterable<string, array{bool, bool, SignOutStatus}>
     */
    public static function provideOutcomes(): iterable
    {
        yield 'every one answered Success' => [true, true, SignOutStatus::Success];
        yield 'one answered otherwise' => [false, true, SignOutStatus::PartialLogout];
        yield 'one passed over' => [true, false, SignOutStatus::PartialLogout];
    }

    /**
     * S-36: the single logout services a chain of the session would go to, the ones the notifier can tell.
     */
    #[Test]
    public function theDestinationsAreTheServicesOfTheServiceProvidersThatCanBeTold(): void
    {
        // Given
        $this->notifier = new RecordingSignOutNotifier([self::REQUESTER]);

        // When / Then
        static::assertSame([self::FIRST . '/slo', self::SECOND . '/slo'], $this->logout()->destinations($this->session));
    }

    /**
     * A session of the tenant, stored, that signed in at the service providers given, in that order.
     *
     * @param list<string> $serviceProviders
     */
    private function sessionSignedInAt(array $serviceProviders): AuthenticationSession
    {
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $this->sessions->save($session);
        foreach ($serviceProviders as $serviceProvider) {
            $this->participations->record(new SessionParticipation(Uuid::v7(), $this->tenant, $session, $serviceProvider, Fixtures::now()));
        }

        return $session;
    }

    private function resumed(LogoutChainStarted|LogoutChainEnded $begun): PostedForm|RedirectedMessage|LogoutChainEnded
    {
        static::assertInstanceOf(LogoutChainStarted::class, $begun);

        return $this->logout()->resume($this->tenant, $begun->reference);
    }

    private function logout(): ProviderLogout
    {
        return new ProviderLogout(
            $this->participations,
            $this->chains,
            $this->sessions,
            $this->notifier,
            $this->responder,
            new FixedSalt(),
            new FixedEndpoints(),
            $this->clock,
        );
    }

    private static function requester(): LogoutRequester
    {
        return new LogoutRequester(self::REQUESTER, SignOutRequests::ID, 'state-1', SignOutRequests::REDIRECT, self::REQUESTER . '/slo');
    }

    private static function progress(): LogoutProgress
    {
        return new LogoutProgress([], [], self::FIRST, false, null, null);
    }
}
