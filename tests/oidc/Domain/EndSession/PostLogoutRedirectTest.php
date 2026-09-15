<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\EndSession;

use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\EndSession\PostLogoutRedirect;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PostLogoutRedirectTest extends TestCase
{
    /**
     * OIDC RP-Initiated Logout 1.0 §3, §2 "state": the registered URI, its query kept, with state
     * added when the request carried one, percent-encoded.
     */
    #[Test]
    public function itRedirectsToTheRegisteredUriWithTheState(): void
    {
        $redirect = new PostLogoutRedirect(new RedirectUri('https://demo.localhost/?app=1'), 'af0ifjsldkj/=');

        static::assertSame('https://demo.localhost/?app=1&state=af0ifjsldkj%2F%3D', $redirect->toUri());
    }

    /**
     * Without state, the URI is the registered one, byte for byte: nothing is added, not even "iss"
     * (RFC 9207 covers authorization responses only), and oidc_login sends none.
     */
    #[Test]
    public function itRedirectsToTheRegisteredUriAsIsWithoutState(): void
    {
        $redirect = new PostLogoutRedirect(new RedirectUri('https://demo.localhost/'), null);

        static::assertSame('https://demo.localhost/', $redirect->toUri());
    }
}
