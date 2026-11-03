<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\ImageSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * CSP Level 3 §6.1: the answer of a page that shows an image served by a host a client named allows that
 * origin and no other, whatever policy the answer carries, and the answer of a page that shows no such
 * image allows none.
 */
final class ImageSourceTest extends TestCase
{
    private const string ENFORCED = 'Content-Security-Policy';

    private const string REPORTED = 'Content-Security-Policy-Report-Only';

    private const string ORIGIN = 'https://cdn.rp.example';

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePoliciesOfAPageThatShowsAnImage(): iterable
    {
        yield 'the one directive, which named this provider' => [
            "img-src 'self'",
            "img-src 'self' " . self::ORIGIN,
        ];
        yield 'among the directives of a deployment, which keep their place and their sources' => [
            "default-src 'none'; img-src 'self' data:; form-action 'self'",
            "default-src 'none'; img-src 'self' data: " . self::ORIGIN . "; form-action 'self'",
        ];
        yield 'a directive that refused every image, which may name no source beside it' => [
            "img-src 'none'",
            'img-src ' . self::ORIGIN,
        ];
        yield 'a directive naming another host, which keeps it' => [
            "img-src 'self' https://cdn.acme.example",
            "img-src 'self' https://cdn.acme.example " . self::ORIGIN,
        ];
        yield 'a directive that already named this one, which is named once' => [
            "img-src 'self' " . self::ORIGIN,
            "img-src 'self' " . self::ORIGIN,
        ];
        yield 'a name written in another case, a directive being matched without regard to case' => [
            "IMG-SRC 'self'",
            "IMG-SRC 'self' " . self::ORIGIN,
        ];
    }

    #[Test]
    #[DataProvider('providePoliciesOfAPageThatShowsAnImage')]
    public function theAnswerOfAPageThatShowsAnImageAllowsTheOriginItIsServedFrom(string $policy, string $expected): void
    {
        // When
        $response = self::answer($policy, [self::ORIGIN]);

        // Then
        static::assertSame($expected, $response->headers->get(self::ENFORCED));
    }

    /**
     * CSP Level 3 §6.1: a fetch directive a policy leaves out is answered by "default-src", so a policy
     * that refuses everything and never mentioned an image is completed with the directive written out of
     * that one, rather than left to refuse the logo the page shows.
     */
    #[Test]
    public function theDirectiveIsWrittenOutOfTheOneItFallsBackToWhenThePolicyNamesThatOneAlone(): void
    {
        // Given
        $policy = "default-src 'none'; script-src 'self'";

        // When
        $response = self::answer($policy, [self::ORIGIN]);

        // Then
        static::assertSame("default-src 'none'; script-src 'self'; img-src " . self::ORIGIN, $response->headers->get(self::ENFORCED));
    }

    /**
     * A policy that names neither directive restricts no image: the directive falls back to one that is
     * not there either, so there is nothing to complete and the policy is the one the answer carried.
     */
    #[Test]
    public function thePolicyOfAPageThatRestrictsNoImageIsTheOneTheAnswerCarried(): void
    {
        // Given
        $policy = "frame-ancestors 'none'";

        // When
        $response = self::answer($policy, [self::ORIGIN]);

        // Then
        static::assertSame($policy, $response->headers->get(self::ENFORCED));
    }

    /**
     * A client that registered no logo, on a tenant that declared none: the page shows no image of
     * anybody's and the policy of its deployment is what it carries.
     */
    #[Test]
    public function thePolicyOfAPageThatShowsNoImageOfAStrangerNamesNoOrigin(): void
    {
        // Given
        $policy = "default-src 'none'; img-src 'self' data:";

        // When
        $response = self::answer($policy, []);

        // Then
        static::assertSame($policy, $response->headers->get(self::ENFORCED));
    }

    /**
     * A deployment that only reports gets the same answer: a report of an image the page is built to show
     * would say nothing to anybody.
     */
    #[Test]
    public function thePolicyThatOnlyReportsIsCompletedToo(): void
    {
        // When
        $response = self::answer("img-src 'self'", [self::ORIGIN], self::REPORTED);

        // Then
        static::assertSame("img-src 'self' " . self::ORIGIN, $response->headers->get(self::REPORTED));
    }

    /**
     * The logo of the client and the logo of the tenant are two origins, and the same host serving both is
     * one: a page names what it shows, and a policy says what it allows one time.
     */
    #[Test]
    public function aPageThatShowsTwoImagesAllowsBothOfTheirOriginsOnce(): void
    {
        // When
        $response = self::answer("img-src 'self'", [self::ORIGIN, 'https://cdn.acme.example', self::ORIGIN]);

        // Then
        static::assertSame(
            "img-src 'self' " . self::ORIGIN . ' https://cdn.acme.example',
            $response->headers->get(self::ENFORCED),
        );
    }

    /**
     * @param list<string> $origins
     */
    private static function answer(string $policy, array $origins, string $header = self::ENFORCED): Response
    {
        $listener = new ImageSource();
        $request = Request::create('https://op.test/consent');
        $listener->mayLoadFrom($request, $origins);
        $response = new Response('a page', Response::HTTP_OK, [$header => $policy]);
        $listener->onKernelResponse(new ResponseEvent(
            static::createStub(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        ));

        return $response;
    }
}
