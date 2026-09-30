<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class Sha256CodeChallengeMethodTest extends TestCase
{
    /**
     * RFC 7636 §4.3: the name a request writes in "code_challenge_method", which RFC 8414 §2 announces in
     * "code_challenge_methods_supported".
     */
    #[Test]
    public function itNamesItselfAsTheRequestWritesIt(): void
    {
        // When / Then
        static::assertSame('S256', new Sha256CodeChallengeMethod()->name());
    }

    /**
     * RFC 7636 §4.6 with the vector of appendix B: BASE64URL(SHA256(ASCII(verifier))) is the challenge.
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
     * RFC 7636 §4.6: one character off, the empty string, the challenge itself (a "plain" attempt) and a
     * padded digest are refused.
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
