<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\CrossSiteSessionCookie;
use App\Saml\IdentityProviderRoutes;
use App\Saml\LogoutChainCookie;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * spec/saml.md S-28, "The plane"
 */
final class CrossSiteSessionCookieTest extends TestCase
{
    private const string SESSION = 'MOCKSESSID';

    /**
     * S-28, S-32
     */
    #[Test]
    public function theSessionCookieAloneIsTakenOff(): void
    {
        // Given
        $request = self::request('POST', 'cross-site');

        // When
        $response = self::answered($request, IdentityProviderRoutes::SINGLE_LOGOUT);

        // Then
        static::assertSame([LogoutChainCookie::NAME], self::namesOf($response));
    }

    /**
     * S-28, "The plane"
     */
    #[Test]
    #[DataProvider('provideRequestsThatKeepTheirSessionCookie')]
    public function anyOtherRequestKeepsTheSessionCookie(Request $request, string $route): void
    {
        // When
        $response = self::answered($request, $route);

        // Then
        static::assertSame([self::SESSION, LogoutChainCookie::NAME], self::namesOf($response));
    }

    /**
     * @return iterable<string, array{Request, string}>
     */
    public static function provideRequestsThatKeepTheirSessionCookie(): iterable
    {
        yield 'a GET from another site' => [self::request('GET', 'cross-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a HEAD from another site' => [self::request('HEAD', 'cross-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from the same site' => [self::request('POST', 'same-site'), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post that does not say where it came from' => [self::request('POST', null), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from another site with the session cookie' => [self::request('POST', 'cross-site', true), IdentityProviderRoutes::SINGLE_LOGOUT];
        yield 'a post from another site to the protocol plane' => [self::request('POST', 'cross-site'), 'beffroi_protocol_token'];
        yield 'a post from another site to a route of the application' => [self::request('POST', 'cross-site'), 'app_home'];
    }

    /**
     * S-28
     */
    #[Test]
    #[DataProvider('provideMethodsLaxKeepsTheCookieFrom')]
    public function aRequestFromAnotherSiteWithoutTheCookieIsOneTheCookieDidNotAccompany(string $method): void
    {
        // When / Then
        static::assertTrue(CrossSiteSessionCookie::withheldFrom(self::request($method, 'cross-site')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMethodsLaxKeepsTheCookieFrom(): iterable
    {
        yield 'POST' => ['POST'];
        yield 'PUT' => ['PUT'];
        yield 'DELETE' => ['DELETE'];
    }

    private static function request(string $method, ?string $site, bool $withTheCookie = false): Request
    {
        $request = Request::create(
            'https://op.test/saml/slo',
            $method,
            [],
            $withTheCookie ? [self::SESSION => 'held'] : [],
            [],
            $site === null ? [] : ['HTTP_SEC_FETCH_SITE' => $site],
        );
        $request->setSession(new Session(new MockArraySessionStorage(self::SESSION)));

        return $request;
    }

    private static function answered(Request $request, string $route): Response
    {
        $request->attributes->set('_route', $route);
        $response = new Response();
        $response->headers->setCookie(Cookie::create(self::SESSION, 'started', 0, '/', null, true, true, false, Cookie::SAMESITE_LAX));
        $response->headers->setCookie(Cookie::create(LogoutChainCookie::NAME, 'secret', 0, '/', null, true, true, false, Cookie::SAMESITE_NONE));
        new CrossSiteSessionCookie()->onKernelResponse(new ResponseEvent(
            static::createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        ));

        return $response;
    }

    /**
     * @return list<string>
     */
    private static function namesOf(Response $response): array
    {
        $names = [];
        foreach ($response->headers->getCookies() as $cookie) {
            $names[] = $cookie->getName();
        }

        return $names;
    }
}
