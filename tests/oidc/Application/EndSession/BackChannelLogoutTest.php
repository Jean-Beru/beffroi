<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\EndSession;

use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use function array_map;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\EndSession\BackChannelLogout;
use Heidi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Back-Channel Logout 1.0 §2.6: who is told that a session ended, and who is not.
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
                new Jwts($this->session->tenant)->signer,
                new PublicSubjectIdentifierResolver(),
                Algorithms::all(),
                new SymfonyUuidGenerator(),
            ),
            $this->events,
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * §2.6: every client the session signed in that registered a URI, and one token each.
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
     * §2.6: a client that registered no back-channel logout URI has nowhere to be told, and no token is
     * minted for it; the clients that come after it are told all the same.
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
     * §2.6: a session and a client, one token, whatever the number of grants the client obtained in it.
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
     * §2.6: a code still waiting at the token endpoint gave the client no session to end.
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
     * A session of another browser keeps its clients: the announcement is per session, which is what
     * "sid" names in the token (§2.4).
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
     * The event carries what the sender needs and nothing it would have to decide: the URI of the client
     * and the compact JWS (architecture §5.6).
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

    /**
     * A client that obtained a token in the session: a grant of the session, exchanged.
     */
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
