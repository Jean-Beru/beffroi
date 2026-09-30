<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use Heidi\Oidc\Application\Authorization\CodeChallengeMethods;
use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\ChallengeMethods;
use Heidi\Oidc\Tests\Fixture\FakeCodeChallengeMethod;
use function array_map;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CodeChallengeMethodsTest extends TestCase
{
    /**
     * RFC 7636 §4.2: the methods the wiring gave the provider, in the order it wired them, which is the
     * order the discovery document announces them in.
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
     * RFC 7636 §4.3: a request names a method, and the name is resolved against the wiring rather than
     * read.
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
     * Decision 0006: "plain" (RFC 7636 §4.2) is a class this module does not ship, so nothing answers to
     * that name, whatever a deployment wires.
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
     * Decision 0006: PKCE is required of every client, so a provider wired to verify no challenge is not
     * one this deployment can be.
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
     * RFC 7636 §4.6: two methods of the same wiring each verify their own challenge, and nothing outside
     * them chooses which transformation is applied.
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
