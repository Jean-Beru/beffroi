<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use DateInterval;
use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\EndSession\BackChannelLogout;
use Beffroi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeLogoutTokenDelivery;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Symfony\Component\Clock\MockClock;

/**
 * Back-Channel Logout 1.0 §2.6
 */
final class BackChannelLogoutTest extends TestCase
{
    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private RecordingEventDispatcher $events;

    private BackChannelLogout $logout;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->events = new RecordingEventDispatcher();
        $this->logout = new BackChannelLogout(
            $this->grants,
            new LogoutTokenIssuer(
                new Jwts($this->session->tenant)->documents,
                Subjects::publicKind(),
                new SymfonyUuidGenerator(),
                new FakeLogoutTokenDelivery(new DateInterval('PT200S')),
            ),
            $this->events,
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function everyClientOfTheSessionThatRegisteredAUriIsTold(): void
    {
        // Given
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'third', 'https://third.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        static::assertSame(['first', 'second', 'third'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientWithoutABackChannelLogoutUriIsNotTold(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));
        $this->signedIn(Clients::withBackChannelLogout($this->session->tenant, 'listening', 'https://listening.example/logout'));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        static::assertSame(['listening'], array_map(
            static fn (LogoutTokenIssued $event): string => $event->clientId,
            $this->events->of(LogoutTokenIssued::class),
        ));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientIsToldOnceWhateverTheNumberOfItsGrants(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->signedIn($client, 'first-grant');
        $this->signedIn($client, 'second-grant');

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        static::assertCount(1, $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientThatNeverExchangedItsCodeIsNotTold(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->grants->save(Tokens::code('unused-code', $client, $this->session, Fixtures::now()));

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Back-Channel Logout 1.0 §2.4
     */
    #[Test]
    public function theClientsOfAnotherSessionAreNotTold(): void
    {
        // Given
        $other = Fixtures::session($this->session->user);
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $grant = Tokens::code('other-code', $client, $other, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        static::assertSame([], $this->events->of(LogoutTokenIssued::class));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function theEventCarriesTheUriAndTheTokenToPostThere(): void
    {
        // Given
        $client = Clients::withBackChannelLogout($this->session->tenant, 'first', 'https://first.example/logout');
        $this->signedIn($client);

        // When
        $this->logout->sessionEnded($this->ended(), Fixtures::context());

        // Then
        [$event] = $this->events->of(LogoutTokenIssued::class);
        static::assertSame('https://first.example/logout', $event->logoutUri->value);
        static::assertSame($this->session->id, $event->sessionId);
        static::assertSame(Fixtures::now()->getTimestamp(), $event->occurredAt->getTimestamp());
        static::assertStringStartsWith('eyJ', $event->token);
    }

    private function signedIn(Client $client, string $code = 'code-of-the-client'): void
    {
        $grant = Tokens::code($code . '-' . $client->registration->clientId, $client, $this->session, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);
    }

    private function ended(): AuthenticationSession
    {
        $this->session->end(SessionEnd::RelyingParty, Fixtures::now());

        return $this->session;
    }
}
