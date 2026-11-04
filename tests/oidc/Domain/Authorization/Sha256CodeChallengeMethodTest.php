<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class Sha256CodeChallengeMethodTest extends TestCase
{
    /**
     * RFC 7636 §4.3, RFC 8414 §2
     */
    #[Test]
    public function itNamesItselfAsTheRequestWritesIt(): void
    {
        // When / Then
        static::assertSame('S256', new Sha256CodeChallengeMethod()->name());
    }

    /**
     * RFC 7636 §4.6, appendix B
     */
    #[Test]
    public function itVerifiesTheCodeVerifierOfRfc7636AppendixB(): void
    {
        // When / Then
        static::assertTrue(new Sha256CodeChallengeMethod()->verifies(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ));
    }

    /**
     * RFC 7636 §4.6
     */
    #[Test]
    #[DataProvider('provideWrongVerifiers')]
    public function itRefusesAVerifierThatDoesNotHashToTheChallenge(string $verifier): void
    {
        // When / Then
        static::assertFalse(new Sha256CodeChallengeMethod()->verifies('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $verifier));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWrongVerifiers(): iterable
    {
        yield 'one character off' => ['dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl'];
        yield 'empty' => [''];
        yield 'the challenge itself' => ['E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'];
        yield 'padded' => ['dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk='];
    }
}
