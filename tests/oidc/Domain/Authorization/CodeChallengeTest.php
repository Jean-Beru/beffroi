<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\FakeCodeChallengeMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class CodeChallengeTest extends TestCase
{
    /**
     * RFC 7636 §4.2
     */
    #[Test]
    #[DataProvider('provideValidChallenges')]
    public function itAcceptsFortyThreeToOneHundredAndTwentyEightUnreservedCharacters(string $value): void
    {
        // When
        $challenge = new CodeChallenge($value, new Sha256CodeChallengeMethod());

        // Then
        static::assertSame($value, $challenge->value);
        static::assertSame('S256', $challenge->method->name());
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
        new CodeChallenge($value, new Sha256CodeChallengeMethod());
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
        yield 'a line feed behind a challenge that would pass' => [str_repeat('a', 43) . "\n"];
    }

    /**
     * RFC 7636 §4.6
     */
    #[Test]
    public function itAsksTheMethodItWasMadeWith(): void
    {
        // Given
        $method = new FakeCodeChallengeMethod();
        $challenge = new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $method);

        // When
        $verified = $challenge->verifies('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');

        // Then
        static::assertTrue($verified);
        static::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $method->challengeItWasHanded);
        static::assertSame('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', $method->verifierItWasHanded);
    }

    /**
     * RFC 7636 §4.6
     */
    #[Test]
    public function itRefusesWhatTheMethodRefuses(): void
    {
        // Given
        $challenge = new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new FakeCodeChallengeMethod(answer: false));

        // When / Then
        static::assertFalse($challenge->verifies('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    }
}
