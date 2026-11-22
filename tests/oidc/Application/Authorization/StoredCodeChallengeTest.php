<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use Beffroi\Oidc\Application\Authorization\StoredCodeChallenge;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7636 §4.3
 */
final class StoredCodeChallengeTest extends TestCase
{
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    private StoredCodeChallenge $challenges;

    protected function setUp(): void
    {
        $this->challenges = new StoredCodeChallenge(ChallengeMethods::s256());
    }

    #[Test]
    public function itWritesTheValueAColumnHoldsItAs(): void
    {
        // Given
        $challenge = new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod());

        // When / Then
        static::assertSame('S256:' . self::CHALLENGE, $this->challenges->document($challenge));
    }

    #[Test]
    public function aChallengeComesBackOutOfItsValue(): void
    {
        // Given
        $challenge = new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod());

        // When / Then
        static::assertEquals($challenge, $this->challenges->of($this->challenges->document($challenge)));
    }

    #[Test]
    #[DataProvider('provideValuesThatAreNotAChallenge')]
    public function aValueThatIsNotAChallengeIsRefused(string $value, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->challenges->of($value);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideValuesThatAreNotAChallenge(): iterable
    {
        yield 'no method' => [self::CHALLENGE, 'A stored code challenge reads "method:challenge", got "' . self::CHALLENGE . '".'];
        yield 'the plain method, which decision 0006 lets nothing wire' => [
            'plain:' . self::CHALLENGE,
            'The code challenge method "plain" is not one of the provider.',
        ];
        yield 'a challenge too short' => [
            'S256:short',
            'The code challenge "short" is not 43 to 128 unreserved characters (RFC 7636 §4.2).',
        ];
    }
}
