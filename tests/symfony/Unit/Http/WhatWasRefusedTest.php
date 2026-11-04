<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\WhatWasRefused;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

final class WhatWasRefusedTest extends TestCase
{
    #[Test]
    public function aRefusalIsTakenByThePageThatWasRedirectedTo(): void
    {
        // Given
        $request = self::request();
        new WhatWasRefused()->keep($request, 'claim_refused', 'zoneinfo');

        // When
        $refusal = new WhatWasRefused()->take($request);

        // Then
        static::assertSame('claim_refused', $refusal?->code);
        static::assertSame('zoneinfo', $refusal->field);
    }

    #[Test]
    public function aRefusalIsGoneOnTheNextRead(): void
    {
        // Given
        $request = self::request();
        $refusals = new WhatWasRefused();
        $refusals->keep($request, 'claim_refused');
        $refusals->take($request);

        // When / Then
        static::assertNull($refusals->take($request));
    }

    #[Test]
    public function aRefusalAboutNoFieldInParticularNamesNone(): void
    {
        // Given
        $request = self::request();
        new WhatWasRefused()->keep($request, 'refused');

        // When / Then
        static::assertNull(new WhatWasRefused()->take($request)?->field);
    }

    #[Test]
    public function aPageNothingWasRefusedOnTakesNothing(): void
    {
        // When / Then
        static::assertNull(new WhatWasRefused()->take(self::request()));
    }

    #[Test]
    public function aRequestWithoutASessionTakesNothing(): void
    {
        // When / Then
        static::assertNull(new WhatWasRefused()->take(new Request()));
    }

    #[Test]
    public function whatIsNotARefusalIsNothing(): void
    {
        // Given
        $request = self::request();
        $request->getSession()->set(WhatWasRefused::KEY, 'claim_refused');

        // When / Then
        static::assertNull(new WhatWasRefused()->take($request));
    }

    private static function request(): Request
    {
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }
}
