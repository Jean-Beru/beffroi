<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class CodeChallengeTest extends TestCase
{
    /**
     * RFC 7636 §4.2: code-challenge = 43*128unreserved, unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~".
     */
    #[Test]
    #[DataProvider('provideValidChallenges')]
    public function itAcceptsFortyThreeToOneHundredAndTwentyEightUnreservedCharacters(string $value): void
    {
        // When
        $challenge = new CodeChallenge($value, CodeChallengeMethod::S256);

        // Then
        static::assertSame($value, $challenge->value);
        static::assertSame('S256', $challenge->method->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidChallenges(): iterable
    {
        yield 'S256 of "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (RFC 7636 appendix B)' => ['E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'];
        yield 'shortest' => [str_repeat('a', 43)];
        yield 'longest' => [str_repeat('b', 128)];
        yield 'every unreserved character' => ['AZaz09-._~' . str_repeat('x', 33)];
    }

    #[Test]
    #[DataProvider('provideInvalidChallenges')]
    public function itRejectsWhatIsNotAChallenge(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('RFC 7636 §4.2');

        // When
        new CodeChallenge($value, CodeChallengeMethod::S256);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidChallenges(): iterable
    {
        yield 'empty' => [''];
        yield 'too short' => [str_repeat('a', 42)];
        yield 'too long' => [str_repeat('a', 129)];
        yield 'base64 padding' => [str_repeat('a', 42) . '='];
        yield 'standard base64 alphabet' => [str_repeat('a', 42) . '+'];
        yield 'space' => [str_repeat('a', 42) . ' '];
    }

    /**
     * RFC 7636 §4.6 with the vector of appendix B: BASE64URL(SHA256(verifier)) is the challenge.
     */
    #[Test]
    public function itVerifiesTheCodeVerifierOfRfc7636AppendixB(): void
    {
        // Given
        $challenge = new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', CodeChallengeMethod::S256);

        // When / Then
        static::assertTrue($challenge->verifies('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    }

    /**
     * RFC 7636 §4.6: one character off, the empty string, or the challenge itself (a "plain" attempt)
     * are refused.
     */
    #[Test]
    #[DataProvider('provideWrongVerifiers')]
    public function itRefusesAVerifierThatDoesNotHashToTheChallenge(string $verifier): void
    {
        // Given
        $challenge = new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', CodeChallengeMethod::S256);

        // When / Then
        static::assertFalse($challenge->verifies($verifier));
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
