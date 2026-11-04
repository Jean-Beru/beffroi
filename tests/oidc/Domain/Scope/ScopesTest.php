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
 * RFC 6749 §3.3
 */
final class ScopesTest extends TestCase
{
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
     * RFC 6749 §3.3
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
     * RFC 6749 §3.3
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
