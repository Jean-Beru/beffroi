<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\EndSession;

use function base64_encode;
use function hash;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Heidi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Front-Channel Logout 1.0 §2: the page itself, and the policy that is part of it.
 */
final class FrontChannelLogoutPageTest extends TestCase
{
    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
    }

    /**
     * One frame per client, in the order the clients were given.
     */
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
     * RFC 6454 §3.2: two clients of one origin are one source in the policy.
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
     * CSP Level 3 §6.1: nothing loads but the frames the clients registered, nothing frames this page,
     * and the one script that moves the browser on is named by its hash.
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

    /**
     * A page with nowhere to continue to runs no script, so it allows none.
     */
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
     * CSP Level 3 §6.6.2.2: the hash is over the text of the script element, which is why that text is a
     * constant.
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
     * §2: a page with no frame has nothing to do; the caller renders none.
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
