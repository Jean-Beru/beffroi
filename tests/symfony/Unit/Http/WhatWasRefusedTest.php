<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\WhatWasRefused;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Issue #481: every form of these pages answers with a redirection, so a refusal crosses it in the session
 * of the browser, for the one read that follows.
 */
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

    /**
     * Shown once: a person reloading the page they were sent to reads the page as it is.
     */
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

    /**
     * A request with no session at all: a page of the account never has one, having asked for a session of
     * the core first, and nothing here is the answer rather than an error.
     */
    #[Test]
    public function aRequestWithoutASessionTakesNothing(): void
    {
        // When / Then
        static::assertNull(new WhatWasRefused()->take(new Request()));
    }

    /**
     * Whatever is in the session under that key, a page reads a refusal or nothing: a session is written by
     * this provider and read back as what it declares.
     */
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
