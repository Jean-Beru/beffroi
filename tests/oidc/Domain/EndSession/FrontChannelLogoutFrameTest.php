<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2: what the logout page loads for one client of an ended session.
 */
final class FrontChannelLogoutFrameTest extends TestCase
{
    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
    }

    /**
     * §2: "iss" and "sid" are added for a client that declared it reads them, and the registered query
     * is kept before them (RFC 3986 §2.1 for the encoding).
     */
    #[Test]
    public function aClientThatReadsTheSessionGetsTheIssuerAndTheSessionIdentifier(): void
    {
        // Given
        $client = Clients::withFrontChannelLogout($this->session->tenant, 'spa', 'https://spa.example/logout?app=1', sessionRequired: true);

        // When
        $frame = FrontChannelLogoutFrame::ofSession($client, $this->session);

        // Then
        static::assertSame(
            'https://spa.example/logout?app=1&iss=https%3A%2F%2Fid.acme.example&sid=' . $this->session->id->toRfc4122(),
            $frame->uri,
        );
    }

    /**
     * §2 makes the two parameters conditional: a client that did not ask for them is loaded on the URI
     * it registered, byte for byte.
     */
    #[Test]
    public function aClientThatDidNotAskReadsItsUriAsRegistered(): void
    {
        // Given
        $client = Clients::withFrontChannelLogout($this->session->tenant, 'spa', 'https://spa.example/logout?app=1');

        // When
        $frame = FrontChannelLogoutFrame::ofSession($client, $this->session);

        // Then
        static::assertSame('https://spa.example/logout?app=1', $frame->uri);
    }

    /**
     * The policy of the page names origins, never paths (RFC 6454 §3.2).
     */
    #[Test]
    public function itKeepsTheOriginOfTheClientBesideTheUri(): void
    {
        // Given
        $client = Clients::withFrontChannelLogout($this->session->tenant, 'spa', 'https://spa.example:8443/logout');

        // When
        $frame = FrontChannelLogoutFrame::ofSession($client, $this->session);

        // Then
        static::assertSame('https://spa.example:8443', $frame->origin);
        static::assertSame('spa', $frame->clientId);
    }

    /**
     * A client that registered nothing is left out of the page by the caller; asking for its frame is a
     * programming error, not a client that is quietly skipped here.
     */
    #[Test]
    public function aClientThatRegisteredNoUriHasNoFrame(): void
    {
        // Given
        $client = Clients::public($this->session->tenant, 'silent');

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('registered no front-channel logout URI');

        // When
        FrontChannelLogoutFrame::ofSession($client, $this->session);
    }
}
