<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use Heidi\Bundle\Http\RequestParameters;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurlencode;
use Symfony\Component\HttpFoundation\Request;

/**
 * RFC 6749 §3.1 and §3.2, RFC 6750 §2.3: where the parameters of a request are read from.
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

    /**
     * A name PHP decodes into a structure of its own reaches the module as the array PHP made of it,
     * for the module to refuse it where its specification takes a single string.
     */
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
     * RFC 8707 §2: "resource" may be sent several times. PHP keeps the last occurrence of a repeated
     * name, so the occurrences are counted on the query itself and handed over as the list they were.
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
     * The same of an encoded form, which is what the token endpoint reads (RFC 6749 §3.2).
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

    /**
     * A name sent once is what PHP decoded of it, whatever the source says.
     */
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

    /**
     * A body of another shape is read by whoever knows that shape, and nothing is counted on it.
     */
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

    /**
     * A key that is not a name is no parameter of the protocol.
     */
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
