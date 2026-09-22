<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\RequestObject;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RequestObjectSigningTest extends TestCase
{
    /**
     * The algorithms the provider is wired with, as the discovery document announces them.
     */
    private const array WIRED = ['RS256', 'PS256', 'ES256', 'EdDSA'];

    /**
     * OIDC Registration §2: what each registration accepts of the "alg" an object carries.
     */
    #[Test]
    #[DataProvider('provideRegistrations')]
    public function aRegistrationAcceptsTheAlgorithmsItNames(RequestObjectSigningInterface $registration, ?string $algorithm, bool $accepted): void
    {
        // When / Then
        static::assertSame($accepted, $registration->accepts($algorithm, self::WIRED));
    }

    /**
     * @return iterable<string, array{RequestObjectSigningInterface, string|null, bool}>
     */
    public static function provideRegistrations(): iterable
    {
        yield 'nothing registered, an algorithm the provider verifies' => [new AnyRegisteredAlgorithm(), 'PS256', true];
        yield 'nothing registered, an algorithm nothing verifies' => [new AnyRegisteredAlgorithm(), 'HS256', false];
        yield 'nothing registered, no algorithm at all' => [new AnyRegisteredAlgorithm(), null, false];
        yield 'nothing registered, an unsigned object' => [new AnyRegisteredAlgorithm(), 'none', false];
        yield 'ES256 registered, ES256' => [new OneRegisteredAlgorithm(Algorithms::es256()), 'ES256', true];
        yield 'ES256 registered, another wired algorithm' => [new OneRegisteredAlgorithm(Algorithms::es256()), 'PS256', false];
        yield 'ES256 registered, an unsigned object' => [new OneRegisteredAlgorithm(Algorithms::es256()), 'none', false];
        yield 'none registered, an unsigned object' => [new UnsignedRequestObjects(), 'none', true];
        yield 'none registered, a signed object' => [new UnsignedRequestObjects(), 'ES256', false];
        yield 'none registered, no algorithm at all' => [new UnsignedRequestObjects(), null, false];
    }

    /**
     * Decision 0006: an algorithm a deployment stopped wiring stops verifying the objects of the client
     * that registered it, without the registration being touched.
     */
    #[Test]
    public function anAlgorithmNothingVerifiesAnyMoreIsRefusedForTheClientThatRegisteredIt(): void
    {
        // Given
        $registration = new OneRegisteredAlgorithm(Algorithms::rs256());

        // When / Then
        static::assertFalse($registration->accepts('RS256', ['PS256', 'ES256', 'EdDSA']));
    }

    /**
     * OIDC Registration §2: what the discovery document announces "none" for, and what a registration
     * naming an algorithm needs the client to publish.
     */
    #[Test]
    #[DataProvider('provideRegistrationShapes')]
    public function aRegistrationSaysWhatItNeedsAndWhatItAccepts(RequestObjectSigningInterface $registration, bool $unsigned, bool $needsKeys): void
    {
        // When / Then
        static::assertSame($unsigned, $registration->acceptsUnsigned());
        static::assertSame($needsKeys, $registration->needsPublishedKeys());
    }

    /**
     * @return iterable<string, array{RequestObjectSigningInterface, bool, bool}>
     */
    public static function provideRegistrationShapes(): iterable
    {
        yield 'nothing registered' => [new AnyRegisteredAlgorithm(), false, false];
        yield 'an algorithm registered' => [new OneRegisteredAlgorithm(Algorithms::es256()), false, true];
        yield 'none registered' => [new UnsignedRequestObjects(), true, false];
    }
}
