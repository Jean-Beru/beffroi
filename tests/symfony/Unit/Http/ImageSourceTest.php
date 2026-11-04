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
 * CSP Level 3 §6.1
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
     * CSP Level 3 §6.1
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

    #[Test]
    public function thePolicyThatOnlyReportsIsCompletedToo(): void
    {
        // When
        $response = self::answer("img-src 'self'", [self::ORIGIN], self::REPORTED);

        // Then
        static::assertSame("img-src 'self' " . self::ORIGIN, $response->headers->get(self::REPORTED));
    }

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
