<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\EndSession;

use function base64_encode;
use function hash;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2
 */
final class FrontChannelLogoutPageTest extends TestCase
{
    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
    }

    #[Test]
    public function itCarriesOneFrameForEachClient(): void
    {
        // When
        $page = new FrontChannelLogoutPage([
            $this->frame('first', 'https://first.example/logout'),
            $this->frame('second', 'https://second.example/logout'),
        ], null);

        // Then
        static::assertSame(['https://first.example/logout', 'https://second.example/logout'], $page->frames);
    }

    /**
     * RFC 6454 §3.2
     */
    #[Test]
    public function twoClientsOfTheSameOriginAreOneSource(): void
    {
        // When
        $page = new FrontChannelLogoutPage([$this->frame('first', 'https://rp.example/one'), $this->frame('second', 'https://rp.example/two')], null);

        // Then
        static::assertSame(['https://rp.example'], $page->origins);
    }

    /**
     * CSP Level 3 §6.1
     */
    #[Test]
    public function thePolicyNamesTheFramesAndTheOneScript(): void
    {
        // Given
        $page = new FrontChannelLogoutPage([
            $this->frame('first', 'https://first.example/logout'),
            $this->frame('second', 'https://second.example/logout'),
        ], 'https://demo.example/');

        // When / Then
        static::assertSame(
            "default-src 'none'; frame-src https://first.example https://second.example; script-src '"
            . $page->scriptHash()
            . "'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            $page->contentSecurityPolicy(),
        );
    }

    #[Test]
    public function aPageThatGoesNowhereAllowsNoScript(): void
    {
        // Given
        $page = new FrontChannelLogoutPage([$this->frame('first', 'https://first.example/logout')], null);

        // When / Then
        static::assertSame(
            "default-src 'none'; frame-src https://first.example; script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            $page->contentSecurityPolicy(),
        );
    }

    /**
     * CSP Level 3 §6.6.2.2
     */
    #[Test]
    public function theHashIsTheOneOfTheScriptTheTemplateRenders(): void
    {
        // Given
        $page = new FrontChannelLogoutPage([$this->frame('first', 'https://first.example/logout')], 'https://demo.example/');

        // When / Then
        static::assertSame('sha256-' . base64_encode(hash('sha256', FrontChannelLogoutPage::SCRIPT, true)), $page->scriptHash());
    }

    /**
     * Front-Channel Logout 1.0 §2
     */
    #[Test]
    public function aPageWithoutAFrameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('at least one frame');

        // When
        new FrontChannelLogoutPage([], null);
    }

    private function frame(string $clientId, string $uri): FrontChannelLogoutFrame
    {
        return FrontChannelLogoutFrame::ofSession(Clients::withFrontChannelLogout($this->session->tenant, $clientId, $uri), $this->session);
    }
}
