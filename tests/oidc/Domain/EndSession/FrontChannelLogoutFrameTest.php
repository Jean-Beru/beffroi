<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2
 */
final class FrontChannelLogoutFrameTest extends TestCase
{
    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
    }

    /**
     * Front-Channel Logout 1.0 §2, RFC 3986 §2.1
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
     * Front-Channel Logout 1.0 §2
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
     * RFC 6454 §3.2
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
