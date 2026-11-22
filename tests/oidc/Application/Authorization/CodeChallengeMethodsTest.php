<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use Beffroi\Oidc\Application\Authorization\CodeChallengeMethods;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use Beffroi\Oidc\Tests\Fixture\FakeCodeChallengeMethod;
use function array_map;
use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CodeChallengeMethodsTest extends TestCase
{
    /**
     * RFC 7636 §4.2
     */
    #[Test]
    public function itHoldsTheMethodsInTheOrderTheyAreWired(): void
    {
        // When
        $methods = ChallengeMethods::s256AndInvented()->codeChallengeMethods();

        // Then
        static::assertSame(['S256', 'S512'], array_map(static fn (CodeChallengeMethodInterface $method): string => $method->name(), $methods));
    }

    /**
     * RFC 7636 §4.3
     */
    #[Test]
    public function itResolvesAMethodByTheNameItGivesItself(): void
    {
        // When
        $method = ChallengeMethods::s256()->codeChallengeMethodNamed('S256');

        // Then
        static::assertInstanceOf(Sha256CodeChallengeMethod::class, $method);
    }

    /**
     * Decision 0006, RFC 7636 §4.2
     */
    #[Test]
    public function itResolvesNothingForANameNothingWiredAnswersTo(): void
    {
        // When / Then
        static::assertNull(ChallengeMethods::s256()->codeChallengeMethodNamed('plain'));
    }

    #[Test]
    public function itRefusesAMethodWiredTwice(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The code challenge method "S256" is wired twice.');

        // When
        new CodeChallengeMethods([new Sha256CodeChallengeMethod(), new Sha256CodeChallengeMethod()]);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function itRefusesAProviderWiredWithNoMethodAtAll(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider verifies a PKCE challenge with at least one method (RFC 7636 section 4.2).');

        // When
        new CodeChallengeMethods([]);
    }

    /**
     * RFC 7636 §4.6
     */
    #[Test]
    public function itResolvesEachWiredMethodToItself(): void
    {
        // When
        $invented = ChallengeMethods::s256AndInvented()->codeChallengeMethodNamed('S512');

        // Then
        static::assertInstanceOf(FakeCodeChallengeMethod::class, $invented);
    }
}
