<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\RequestParameters;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurlencode;
use Symfony\Component\HttpFoundation\Request;

/**
 * RFC 6749 §3.1, §3.2, RFC 6750 §2.3
 */
final class RequestParametersTest extends TestCase
{
    #[Test]
    public function aBrowserGetReadsTheQuery(): void
    {
        // Given
        $request = Request::create('/authorize?client_id=demo&scope=openid', 'GET');

        // When / Then
        static::assertSame(
            [
                'client_id' => 'demo',
                'scope' => 'openid',
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }

    #[Test]
    public function aBrowserPostReadsTheFormBodyAndNotTheQuery(): void
    {
        // Given
        $request = Request::create('/authorize?client_id=from-the-query', 'POST', [
            'client_id' => 'from-the-body',
        ]);

        // When / Then
        static::assertSame(
            [
                'client_id' => 'from-the-body',
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }

    #[Test]
    public function aFormReadsTheBodyOnly(): void
    {
        // Given
        $request = Request::create('/token?grant_type=from-the-query', 'POST', [
            'grant_type' => 'from-the-body',
        ]);

        // When / Then
        static::assertSame(
            [
                'grant_type' => 'from-the-body',
            ],
            RequestParameters::ofForm($request),
        );
    }

    #[Test]
    public function aParameterPhpDecodesIntoAnArrayIsHandedOverAsOne(): void
    {
        // Given
        $request = Request::create('/authorize?scope[]=openid&scope[]=profile', 'GET');

        // When / Then
        static::assertSame(
            [
                'scope' => ['openid', 'profile'],
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aNameTheQueryCarriesTwiceIsHandedOverAsTheListItWas(): void
    {
        // Given
        $request = Request::create(
            '/authorize?client_id=demo&resource=' . rawurlencode('https://cal.example.com/') . '&resource=' . rawurlencode('https://contacts.example.com/'),
            'GET',
        );

        // When / Then
        static::assertSame(
            [
                'client_id' => 'demo',
                'resource' => ['https://cal.example.com/', 'https://contacts.example.com/'],
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }

    /**
     * RFC 6749 §3.2
     */
    #[Test]
    public function aNameTheFormCarriesTwiceIsHandedOverAsTheListItWas(): void
    {
        // Given
        $request = Request::create(
            '/token',
            'POST',
            [
                'grant_type' => 'authorization_code',
            ],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            ],
            'grant_type=authorization_code&resource=https%3A%2F%2Fcal.example.com%2F&resource=https%3A%2F%2Fcontacts.example.com%2F',
        );

        // When / Then
        static::assertSame(
            [
                'grant_type' => 'authorization_code',
                'resource' => ['https://cal.example.com/', 'https://contacts.example.com/'],
            ],
            RequestParameters::ofForm($request),
        );
    }

    #[Test]
    public function aNameSentOnceKeepsTheValuePhpDecoded(): void
    {
        // Given
        $request = Request::create('/authorize?login_hint=' . rawurlencode('alice smith'), 'GET');

        // When / Then
        static::assertSame(
            [
                'login_hint' => 'alice smith',
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }

    #[Test]
    public function nothingIsCountedOnABodyThatIsNotAnEncodedForm(): void
    {
        // Given
        $request = Request::create(
            '/token',
            'POST',
            [
                'grant_type' => 'authorization_code',
            ],
            [],
            [],
            [
                'CONTENT_TYPE' => 'application/json',
            ],
            '{"resource":"https://cal.example.com/"}',
        );

        // When / Then
        static::assertSame(
            [
                'grant_type' => 'authorization_code',
            ],
            RequestParameters::ofForm($request),
        );
    }

    #[Test]
    public function aNumericKeyIsDropped(): void
    {
        // Given
        $request = Request::create('/authorize?0=zero&client_id=demo', 'GET');

        // When / Then
        static::assertSame(
            [
                'client_id' => 'demo',
            ],
            RequestParameters::ofBrowserRequest($request),
        );
    }
}
