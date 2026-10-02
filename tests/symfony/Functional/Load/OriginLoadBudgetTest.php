<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Load;

use Beffroi\Bundle\Load\LoadBudget;
use Beffroi\Bundle\Load\LoadRefusal;
use Beffroi\Bundle\Plane\Plane;
use Beffroi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use Beffroi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_replace;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0014 over HTTP: the budget of the origin of a request is consumed on every route of the two
 * planes (architecture §5.2), before the firewall and before anything the request asks for, and the
 * request that finds the window full is answered `429` in the shape of its plane. The budget of this
 * kernel is one request, named before the kernel boots as a deployment names its own, and the browser
 * keeps its kernel so that the count of a window survives between two requests.
 */
final class OriginLoadBudgetTest extends BrowserTestCase
{
    /**
     * The address the budget is spent on. Its own, so that nothing this suite sends from anywhere else
     * is counted here.
     */
    private const string ADDRESS = '198.51.100.7';

    private const string OTHER_ADDRESS = '198.51.100.8';

    private const int BUDGET = 1;

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_ORIGIN_BUDGET'] = (string) self::BUDGET;
        parent::setUp();
        $this->browser->disableReboot();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_ORIGIN_BUDGET'], $_ENV['BEFFROI_TEST_ORIGIN_BUDGET']);
    }

    /**
     * The acceptance of issue #178: a route is covered because it is routed, and the refusal has one
     * shape. Every route of the two planes is asked for once the budget of this address is spent, and
     * the test names the one that was served or answered without the delay to wait, the way the events
     * of the module are covered by being in their directory.
     */
    #[Test]
    public function everyRouteOfTheTwoPlanesIsRefusedWithTheDelayToWait(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $served = [];
        foreach (self::planeRoutes() as $name => $request) {
            $this->browser->request($request[0], $request[1], server: self::from(self::ADDRESS));
            $response = $this->browser->getResponse();
            if ($response->getStatusCode() !== LoadRefusal::STATUS || (int) $response->headers->get('Retry-After') <= 0) {
                $served[] = sprintf('%s (%s %s): %d', $name, $request[0], $request[1], $response->getStatusCode());
            }
        }

        // Then
        static::assertSame([], $served);
    }

    /**
     * Decision 0014: the routes of the host application are not the bundle's, and nothing of what they
     * cost is this provider's to bound.
     */
    #[Test]
    public function aRouteOfTheHostApplicationIsNotCounted(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/host', server: self::from(self::ADDRESS));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014: the key is the address, and what it bounds is the load one origin makes. Another
     * address has its own window, whatever the first one spent.
     */
    #[Test]
    public function theBudgetIsCountedByAddress(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::OTHER_ADDRESS));

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014, RFC 6585 §4 and RFC 9126 §2.3: `429`, the delay to wait, nothing cached, and a body
     * that explains the condition without an `error` member, none of the registered values saying that a
     * budget is spent (RFC 6749 §11.4).
     */
    #[Test]
    public function theRefusalOfTheProtocolPlaneIsADocumentWithoutAnErrorMember(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
        $members = self::json($response);
        static::assertArrayNotHasKey('error', $members);
        static::assertSame(LoadRefusal::DESCRIPTION, $members['error_description']);
    }

    /**
     * Decision 0014: on the interaction plane a refusal is the error page of the plane with its code, as
     * the code page names `too_many_attempts`, and with the headers every page of the plane carries.
     */
    #[Test]
    public function theRefusalOfTheInteractionPlaneIsTheErrorPageOfThePlane(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/login', server: self::from(self::ADDRESS));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
        self::assertInteractionHeaders($response);
        static::assertSame(LoadRefusal::PAGE_ERROR, $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
    }

    /**
     * Architecture §5.7: a page of the interaction plane is read by somebody, and the budget is consumed
     * above the listener that chooses the language, so the refusal chooses it itself.
     */
    #[Test]
    public function theRefusedPageIsInTheLanguageTheBrowserAsksFor(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request(
            'GET',
            '/login',
            server: self::from(self::ADDRESS)
            + [
                'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
            ],
        );

        // Then
        static::assertSame('fr', $this->browser->getCrawler()->filter('html')->attr('lang'));
    }

    /**
     * Decision 0014: the budget is consumed before the firewall opens a session or hashes anything, so a
     * page that answers "sign in first" answers the refusal instead.
     */
    #[Test]
    public function thePageOfAnAccountIsRefusedBeforeItAsksForASession(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/account/passkeys', server: self::from(self::ADDRESS));

        // Then
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Decision 0014: a refusal reaches the audit trail with the budget that refused, the route asked
     * for, the origin of the request, and no client, no budget of a client having been consumed.
     */
    #[Test]
    public function aRefusalReachesTheAuditTrail(): void
    {
        // Given
        $this->spendTheBudget();

        // When
        $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));

        // Then
        $spent = self::refusals();
        static::assertCount(1, $spent);
        static::assertSame(LoadBudget::ORIGIN, $spent[0]->budget);
        static::assertSame('beffroi_protocol_jwks', $spent[0]->route);
        static::assertNull($spent[0]->client);
        static::assertSame(self::ADDRESS, $spent[0]->context->ipAddress);
    }

    /**
     * The one request this address is allowed, which is served and leaves the window full.
     */
    private function spendTheBudget(): void
    {
        for ($request = 1; $request <= self::BUDGET; ++$request) {
            $this->browser->request('GET', '/jwks', server: self::from(self::ADDRESS));
            static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        }
    }

    /**
     * Every route of the two planes, with a method it answers, read from the router of the kernel and
     * from no list of this suite.
     *
     * @return iterable<string, array{string, string}>
     */
    private static function planeRoutes(): iterable
    {
        foreach (self::service('router', RouterInterface::class)->getRouteCollection() as $name => $route) {
            if (Plane::ofRoute($name) === null) {
                continue;
            }
            $methods = $route->getMethods();

            yield self::string($name) => [$methods === [] ? 'GET' : $methods[0], self::pathOf($route)];
        }
    }

    /**
     * The path of a route, with a value the requirements of every variable take: a budget is consumed
     * once a request is matched to a route, so a route with a variable is asked for with one.
     */
    private static function pathOf(Route $route): string
    {
        $path = $route->getPath();
        foreach ($route->compile()->getPathVariables() as $variable) {
            $path = str_replace(sprintf('{%s}', self::string($variable)), Uuid::v7()->toRfc4122(), $path);
        }

        return $path;
    }

    /**
     * @return array<string, string>
     */
    private static function from(string $address): array
    {
        return [
            'REMOTE_ADDR' => $address,
        ];
    }

    /**
     * @return list<LoadBudgetSpent>
     */
    private static function refusals(): array
    {
        $refusals = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LoadBudgetSpent) {
                $refusals[] = $event;
            }
        }

        return $refusals;
    }
}
