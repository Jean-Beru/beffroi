<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\EndSession\FrontChannelLogout;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2, §3
 */
final class FrontChannelLogoutTest extends TestCase
{
    private AuthenticationSession $session;

    private InMemoryAuthorizationCodeRepository $grants;

    private FrontChannelLogout $logout;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $this->logout = new FrontChannelLogout($this->grants);
    }

    /**
     * Front-Channel Logout 1.0 §2
     */
    #[Test]
    public function eachClientOfTheSessionThatRegisteredAUriGetsAFrame(): void
    {
        // Given
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], null);

        // Then
        static::assertSame(['https://first.example/logout', 'https://second.example/logout'], $page?->frames);
    }

    /**
     * Front-Channel Logout 1.0 §3
     */
    #[Test]
    public function aClientWithoutAUriIsNotLoaded(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'loaded', 'https://loaded.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], null);

        // Then
        static::assertSame(['https://loaded.example/logout'], $page?->frames);
    }

    #[Test]
    public function aSessionWithNoSuchClientHasNoPage(): void
    {
        // Given
        $this->signedIn(Clients::public($this->session->tenant, 'silent'));

        // When / Then
        static::assertNull($this->logout->pageFor([$this->session], null));
    }

    /**
     * RP-Initiated Logout §3
     */
    #[Test]
    public function thePageCarriesWhereTheBrowserGoesNext(): void
    {
        // Given
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));

        // When
        $page = $this->logout->pageFor([$this->session], 'https://demo.example/?state=x');

        // Then
        static::assertSame('https://demo.example/?state=x', $page?->continueTo);
    }

    /**
     * Front-Channel Logout 1.0 §2, beffroi/saml S-35
     */
    #[Test]
    public function theClientsOfEverySessionEndedGetTheirFrames(): void
    {
        // Given
        $second = Fixtures::session($this->session->user);
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'first', 'https://first.example/logout'));
        $this->signedIn(Clients::withFrontChannelLogout($this->session->tenant, 'second', 'https://second.example/logout'), $second);

        // When
        $page = $this->logout->pageFor([$this->session, $second], null);

        // Then
        static::assertSame(['https://first.example/logout', 'https://second.example/logout'], $page?->frames);
    }

    private function signedIn(Client $client, ?AuthenticationSession $session = null): void
    {
        $grant = Tokens::code('code-of-' . $client->registration->clientId, $client, $session ?? $this->session, Fixtures::now());
        $grant->consume(Fixtures::now());
        $this->grants->save($grant);
    }
}
