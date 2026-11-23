<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Ticket;

use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Application\Ticket\TicketRedeeming;
use Beffroi\Core\Application\Ticket\TotpTicketRedemption;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Application\Totp\BackupCodeSet;
use Beffroi\Core\Application\Totp\TotpCodeMatcher;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryTotpTicketRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\SectionsOneAtATime;
use Beffroi\Core\Tests\Fixture\Totps;
use function count;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;

/**
 * Decision 0026
 */
final class TotpTicketRedemptionTest extends TestCase
{
    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryCredentialRepository $credentials;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryTotpTicketRepository $tickets;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private TotpTicketRedemption $redemption;

    /**
     * @var IssuedTicket<TotpTicket>
     */
    private IssuedTicket $issued;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->hasher = new FakePasswordHasher();
        $this->credentials = new InMemoryCredentialRepository();
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->tickets = new InMemoryTotpTicketRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-11-17T12:00:15+00:00');
        $sections = new SectionsOneAtATime();
        $notifier = new RecordingCredentialChangeNotifier();
        $this->redemption = new TotpTicketRedemption(
            $this->tickets,
            new TicketRedeeming($this->hasher, new DecoyHash($this->hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock()), $this->clock, $sections),
            new TotpEnrolment(
                $this->credentials,
                new EnrolmentRefusal(new FederatedDomains(new InMemoryUpstreamProviders())),
                new SymfonyUuidGenerator(),
                new PlatformRandomness(),
                new BackupCodeSet(new PlatformRandomness(), $this->hasher),
                new ActiveTotp(new ActiveCredentials($this->credentials)),
                Totps::algorithm(),
                new TotpCodeMatcher(Totps::algorithm()),
                Totps::sealer(),
                new CredentialRevocation($this->credentials, $this->clock, $this->events, $notifier),
                $this->clock,
                $this->events,
                $notifier,
            ),
            new OtherSessionsTermination($this->sessions, new SessionTerminator($this->sessions, $this->clock, $this->events)),
        );
        $this->issued = $this->ticketOf($this->alice);
    }

    #[Test]
    public function theTicketOfTheLinkOpens(): void
    {
        // When
        $ticket = $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, $this->issued->value);

        // Then
        static::assertSame($this->issued->ticket, $ticket);
    }

    #[Test]
    public function aWrongValueOpensNothing(): void
    {
        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('This ticket opens nothing.');

        // When
        $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, 'not the value of the link');
    }

    #[Test]
    public function theSecretOfAnAppIsDrawnForAPersonWhoHoldsOneAlready(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, $this->hasher));

        // When
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // Then
        static::assertCount(10, $provisioning->backupCodes);
    }

    #[Test]
    public function theAppEnrolledReplacesTheOneHeld(): void
    {
        // Given
        $held = Totps::credential($this->alice, $this->hasher);
        $this->credentials->save($held);
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // When
        $totp = $this->spend($provisioning);

        // Then
        static::assertSame([true, $totp], [$held->isRevoked(), $this->activeTotp()]);
    }

    #[Test]
    public function aPersonWithoutAnAppEnrolsTheirFirst(): void
    {
        // Given
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // When
        $totp = $this->spend($provisioning);

        // Then
        static::assertSame($totp, $this->activeTotp());
    }

    #[Test]
    public function theTicketIsSpentOnceTheAppIsEnrolled(): void
    {
        // Given
        $this->spend($this->redemption->begin($this->issued->ticket));

        // Then
        $this->expectException(TicketRefusedException::class);

        // When
        $this->redemption->redeem($this->alice->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function aTicketAnotherRedemptionSpentMeanwhileIsRefused(): void
    {
        // Given
        $provisioning = $this->redemption->begin($this->issued->ticket);
        $this->spentByAnotherRedemption();

        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs('This ticket opens nothing.');

        // When
        $this->spend($provisioning);
    }

    /**
     * Decision 0026
     */
    #[Test]
    public function aTicketAnotherRedemptionSpentMeanwhileEnrolsNoApp(): void
    {
        // Given
        $provisioning = $this->redemption->begin($this->issued->ticket);
        $this->spentByAnotherRedemption();

        // When
        try {
            $this->spend($provisioning);
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertNull($this->activeTotp());
    }

    #[Test]
    public function everySessionOfThePersonEndsWithTheSecretItOpenedWith(): void
    {
        // Given
        $here = Fixtures::session($this->alice, $this->clock->now());
        $there = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($here);
        $this->sessions->save($there);
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // When
        $this->spend($provisioning);

        // Then
        static::assertSame(
            [SessionEnd::User, SessionEnd::User, 2],
            [$here->endedBy, $there->endedBy, count($this->events->of(AuthenticationSessionEnded::class))],
        );
    }

    #[Test]
    public function aCodeThatDoesNotMatchIsRefused(): void
    {
        // Given
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The code does not match the secret.');

        // When
        $this->redemption->spend(
            $this->issued->ticket,
            $provisioning,
            self::aCodeThatDoesNotMatch($provisioning, $this->clock->now()),
            Fixtures::context($this->clock->now()),
        );
    }

    #[Test]
    public function aCodeRefusedLeavesTheTicketToSpendTheAppHeldAndTheSessionsOpen(): void
    {
        // Given
        $held = Totps::credential($this->alice, $this->hasher);
        $this->credentials->save($held);
        $session = Fixtures::session($this->alice, $this->clock->now());
        $this->sessions->save($session);
        $provisioning = $this->redemption->begin($this->issued->ticket);

        // When
        try {
            $this->redemption->spend(
                $this->issued->ticket,
                $provisioning,
                self::aCodeThatDoesNotMatch($provisioning, $this->clock->now()),
                Fixtures::context($this->clock->now()),
            );
        } catch (CredentialEnrolmentFailedException) {
        }

        // Then
        static::assertSame([false, false, false], [$this->issued->ticket->isSpent(), $held->isRevoked(), $session->hasEnded()]);
    }

    /**
     * Decision 0025: a floor raised once the ticket was issued refuses the app it would enrol.
     */
    #[Test]
    public function aTenantThatAdmitsNoCodeDrawsNoSecretForATicket(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant(), 'carol');
        $ticket = new TotpTicket(Uuid::v7(), $carol, $this->hasher->hash('the value'), $this->clock->now(), $this->clock->now()->modify('+72 hours'));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);

        // When
        $this->redemption->begin($ticket);
    }

    private function spend(TotpProvisioning $provisioning): TotpCredential
    {
        return $this->redemption->spend(
            $this->issued->ticket,
            $provisioning,
            Totps::codeAt($this->clock->now(), $provisioning->secret),
            Fixtures::context($this->clock->now()),
        );
    }

    /**
     * What the store holds once another request has redeemed the same ticket: its row spent.
     */
    private function spentByAnotherRedemption(): void
    {
        $this->issued->ticket->spend($this->clock->now());
        $this->tickets->save($this->issued->ticket);
    }

    private function activeTotp(): ?TotpCredential
    {
        return new ActiveTotp(new ActiveCredentials($this->credentials))->of($this->alice);
    }

    private static function aCodeThatDoesNotMatch(TotpProvisioning $provisioning, DateTimeImmutable $now): string
    {
        return Totps::codeAt($now->modify('-2 minutes'), $provisioning->secret);
    }

    /**
     * @return IssuedTicket<TotpTicket>
     */
    private function ticketOf(User $user): IssuedTicket
    {
        return new TicketIssuing(new SymfonyUuidGenerator(), new PlatformRandomness(), $this->hasher, $this->clock)->issue(
            $this->tickets,
            $user,
            static fn (
                Uuid $id,
                User $user,
                PasswordHash $secret,
                DateTimeImmutable $issuedAt,
                DateTimeImmutable $expiresAt,
            ): TotpTicket => new TotpTicket($id, $user, $secret, $issuedAt, $expiresAt),
        );
    }
}
