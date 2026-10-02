<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Scope;

use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function array_map;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A set of scopes as RFC 6749 §3.3 writes one. Everything that keeps a scope list holds one of these, so
 * whether a set holds a scope, whether it covers another and how it is written on the wire are answered
 * here and nowhere else.
 */
final class ScopesTest extends TestCase
{
    /**
     * Nothing this provider keeps grants nothing: a request, a consent, a code, a token and a client
     * registration all name what they are for.
     */
    #[Test]
    public function aSetHoldsAtLeastOneScope(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A set of scopes holds at least one scope (RFC 6749 section 3.3).');

        // When
        new Scopes([]);
    }

    /**
     * RFC 6749 §3.3: a set, so a scope named twice counts once, in the order it was first seen.
     */
    #[Test]
    public function aScopeNamedTwiceCountsOnce(): void
    {
        // When
        $scopes = new Scopes([new Scope('profile'), Scope::openid(), new Scope('profile')]);

        // Then
        static::assertSame(['profile', 'openid'], $scopes->values());
    }

    #[Test]
    public function aSetHoldsWhatItWasGiven(): void
    {
        // Given
        $scopes = new Scopes([Scope::openid(), new Scope('email')]);

        // When / Then
        static::assertTrue($scopes->has(new Scope('email')));
    }

    #[Test]
    public function aSetDoesNotHoldWhatItWasNotGiven(): void
    {
        // Given
        $scopes = new Scopes([Scope::openid()]);

        // When / Then
        static::assertFalse($scopes->has(new Scope('email')));
    }

    /**
     * @param list<string> $held
     * @param list<string> $asked
     */
    #[Test]
    #[DataProvider('provideCoverage')]
    public function aSetCoversAnotherWhenItHoldsEveryScopeOfIt(array $held, array $asked, bool $covers): void
    {
        // Given
        $scopes = new Scopes(array_map(static fn (string $value): Scope => new Scope($value), $held));

        // When / Then
        static::assertSame($covers, $scopes->covers(new Scopes(array_map(static fn (string $value): Scope => new Scope($value), $asked))));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, bool}>
     */
    public static function provideCoverage(): iterable
    {
        yield 'the same set' => [['openid', 'email'], ['openid', 'email'], true];
        yield 'a narrower set' => [['openid', 'email'], ['openid'], true];
        yield 'a wider set' => [['openid'], ['openid', 'email'], false];
        yield 'a disjoint set' => [['openid'], ['email'], false];
    }

    /**
     * RFC 6749 §3.3: space delimited, in the order the set holds them.
     */
    #[Test]
    public function aSetWritesItselfSpaceDelimited(): void
    {
        // When / Then
        static::assertSame('openid email', (string) new Scopes([Scope::openid(), new Scope('email')]));
    }

    #[Test]
    public function aSetReadsBackWhatItWrote(): void
    {
        // Given
        $scopes = new Scopes([Scope::openid(), new Scope('email')]);

        // When / Then
        static::assertTrue(Scopes::parse((string) $scopes)->equals($scopes));
    }

    #[Test]
    public function aParameterThatIsNotAScopeListIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        Scopes::parse('open"id');
    }
}
