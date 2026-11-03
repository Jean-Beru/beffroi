<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Closure;
use const E_DEPRECATED;
use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\Test;
use function restore_error_handler;
use function set_error_handler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The root of this application (config/routes/home.yaml, architecture §5.2): the issuer is the origin alone,
 * the bundle never takes the root of the application that installs it, and what "/" answers here is the home
 * of the account.
 */
final class RootOfTheApplicationTest extends BrowserTestCase
{
    /**
     * RFC 9110 §15.4.3: a temporary redirection, after which a browser goes on asking the root. What the root
     * answers is a decision of this application, and a permanent redirection is heuristically cacheable
     * (§15.4.2), so a browser could keep the account in its place.
     */
    #[Test]
    public function theRootSendsTheBrowserToTheHomeOfTheAccount(): void
    {
        // When
        $this->browser->request('GET', '/');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://localhost/account', $response->headers->get('Location'));
    }

    /**
     * Issue #906: a redirection through the controller of FrameworkBundle reaches it by a service that
     * symfony/routing 8.2 deprecates, and the container raises that deprecation each time it hands the service
     * over, so at every request to the root, on the "deprecation" channel of a production kernel. The route
     * redirects by the routing option, whose controller is a service of its own.
     */
    #[Test]
    public function aRequestToTheRootRaisesNoDeprecation(): void
    {
        // When
        $deprecations = self::deprecationsRaisedWhile(fn (): object => $this->browser->request('GET', '/'));

        // Then
        static::assertSame([], $deprecations);
    }

    /**
     * Every deprecation raised while the call runs, the ones "@" silences included: a service of Symfony
     * raises its deprecation silenced (trigger_deprecation()), and the error handler of the kernel still
     * writes it to the "deprecation" channel, which is where a deployment reads it.
     *
     * @param Closure(): mixed $call
     *
     * @return list<string>
     */
    private static function deprecationsRaisedWhile(Closure $call): array
    {
        $deprecations = [];
        set_error_handler(static function (int $level, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_DEPRECATED | E_USER_DEPRECATED);
        try {
            $call();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
