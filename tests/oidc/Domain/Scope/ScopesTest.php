<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Scope;

use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function array_fill;
use function array_map;
use function hrtime;
use function implode;
use function range;
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
    public function theFirstOfTwoEqualScopesIsTheOneKept(): void
    {
        // Given
        $first = new Scope('profile');

        // When
        $scopes = new Scopes([$first, Scope::openid(), new Scope('profile')]);

        // Then
        static::assertSame($first, $scopes->all[0]);
    }

    #[Test]
    public function aSetOfTwentyThousandScopesIsBuiltInLessThanASecond(): void
    {
        // Given
        $given = self::scopes(20_000);

        // When
        $start = hrtime(true);
        $scopes = new Scopes($given);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(20_000, $scopes);
        static::assertLessThan(1_000, $milliseconds);
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
        yield 'a scope in another case' => [['openid'], ['OpenID'], false];
        yield 'a scope of other digits' => [['1'], ['01'], false];
    }

    #[Test]
    public function aSetCoversAnotherOfTwentyThousandScopesInLessThanASecond(): void
    {
        // Given
        $held = new Scopes(self::scopes(20_000));
        $asked = new Scopes(self::scopes(20_000));

        // When
        $start = hrtime(true);
        $covers = $held->covers($asked);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertTrue($covers);
        static::assertLessThan(1_000, $milliseconds);
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

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function aParameterOfAHundredScopesIsRead(): void
    {
        // When
        $scopes = Scopes::parse(implode(' ', self::names(100)));

        // Then
        static::assertCount(100, $scopes);
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function aParameterOfMoreThanAHundredScopesIsRefusedBeforeAnyIsRead(): void
    {
        // Given
        $scope = implode(' ', array_fill(0, 101, 'open"id'));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A scope parameter names 100 scopes at most.');

        // When
        Scopes::parse($scope);
    }

    /**
     * @return list<Scope>
     */
    private static function scopes(int $count): array
    {
        return array_map(static fn (string $name): Scope => new Scope($name), self::names($count));
    }

    /**
     * @return list<string>
     */
    private static function names(int $count): array
    {
        return array_map(static fn (int $index): string => 'scope.' . $index, range(1, $count));
    }
}
