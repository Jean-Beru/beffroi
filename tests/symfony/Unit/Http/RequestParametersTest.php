<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use Heidi\Bundle\Http\RequestParameters;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * RFC 6749 §3.1 and §3.2, RFC 6750 §2.3: where the parameters of a request are read from.
 */
final class RequestParametersTest extends TestCase
{
    #[Test]
    public function aBrowserGetReadsTheQuery(): void
    {
        $request = Request::create('/authorize?client_id=demo&scope=openid', 'GET');

        static::assertSame([
            'client_id' => 'demo',
            'scope' => 'openid',
        ], RequestParameters::ofBrowserRequest($request));
    }

    #[Test]
    public function aBrowserPostReadsTheFormBodyAndNotTheQuery(): void
    {
        $request = Request::create('/authorize?client_id=from-the-query', 'POST', [
            'client_id' => 'from-the-body',
        ]);

        static::assertSame([
            'client_id' => 'from-the-body',
        ], RequestParameters::ofBrowserRequest($request));
    }

    #[Test]
    public function aFormReadsTheBodyOnly(): void
    {
        $request = Request::create('/token?grant_type=from-the-query', 'POST', [
            'grant_type' => 'from-the-body',
        ]);

        static::assertSame([
            'grant_type' => 'from-the-body',
        ], RequestParameters::ofForm($request));
    }

    /**
     * A repeated parameter reaches the module as the array PHP decoded, for the module to refuse it.
     */
    #[Test]
    public function aRepeatedParameterIsHandedOverAsAnArray(): void
    {
        $request = Request::create('/authorize?scope[]=openid&scope[]=profile', 'GET');

        static::assertSame([
            'scope' => ['openid', 'profile'],
        ], RequestParameters::ofBrowserRequest($request));
    }

    /**
     * A key that is not a name is no parameter of the protocol.
     */
    #[Test]
    public function aNumericKeyIsDropped(): void
    {
        $request = Request::create('/authorize?0=zero&client_id=demo', 'GET');

        static::assertSame([
            'client_id' => 'demo',
        ], RequestParameters::ofBrowserRequest($request));
    }
}
