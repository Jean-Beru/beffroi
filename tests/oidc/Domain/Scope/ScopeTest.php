<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Scope;

use function array_map;
use Beffroi\Oidc\Domain\Scope\Scope;
use function hrtime;
use function implode;
use function range;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ScopeTest extends TestCase
{
    /**
     * RFC 6749 §3.3
     */
    #[Test]
    #[DataProvider('provideScopeTokens')]
    public function itIsAScopeToken(string $scope): void
    {
        // When / Then
        static::assertSame($scope, (string) new Scope($scope));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideScopeTokens(): iterable
    {
        yield 'openid' => ['openid'];
        yield 'a URL' => ['https://api.example/read'];
        yield 'every allowed punctuation' => ['!#$%&\'()*+,-./:;<=>?@[]^_`{|}~'];
    }

    #[Test]
    public function openidIsAScope(): void
    {
        // When / Then
        static::assertSame('openid', (string) Scope::openid());
    }

    /**
     * OIDC Core §11
     */
    #[Test]
    public function offlineAccessIsAScope(): void
    {
        // When / Then
        static::assertSame('offline_access', (string) Scope::offlineAccess());
    }

    #[Test]
    public function itEqualsAScopeOfTheSameValue(): void
    {
        // When / Then
        static::assertTrue(Scope::openid()->equals(new Scope('openid')));
    }

    #[Test]
    public function itComparesCaseSensitively(): void
    {
        // When / Then
        static::assertFalse(Scope::openid()->equals(new Scope('OpenID')));
    }

    #[Test]
    #[DataProvider('provideInvalidScopes')]
    public function itRejectsWhatIsNotAScopeToken(string $scope): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('RFC 6749 §3.3');

        // When
        new Scope($scope);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidScopes(): iterable
    {
        yield 'empty' => [''];
        yield 'space' => ['openid profile'];
        yield 'double quote' => ['open"id'];
        yield 'backslash' => ['open\\id'];
        yield 'control character' => ["open\tid"];
        yield 'beyond ASCII' => ['profilé'];
        yield 'a line feed behind a token that would pass' => ["openid\n"];
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function itParsesASpaceDelimitedListInOrder(): void
    {
        // When
        $scopes = Scope::parseList('openid profile email');

        // Then
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $scopes));
    }

    #[Test]
    public function aListIsASetTheFirstOccurrenceWins(): void
    {
        // When
        $scopes = Scope::parseList('profile openid profile');

        // Then
        static::assertSame(['profile', 'openid'], array_map(strval(...), $scopes));
    }

    /**
     * RFC 6749 §3.3
     *
     * @param list<string> $kept
     */
    #[Test]
    #[DataProvider('provideListsWithRepeats')]
    public function aTokenIsTheSameAsAnotherWhenItIsWrittenTheSame(string $list, array $kept): void
    {
        // When
        $scopes = Scope::parseList($list);

        // Then
        static::assertSame($kept, array_map(strval(...), $scopes));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideListsWithRepeats(): iterable
    {
        yield 'in another case' => ['openid OpenID openid', ['openid', 'OpenID']];
        yield 'made of digits' => ['2 1 02 2 1', ['2', '1', '02']];
    }

    #[Test]
    public function itReadsTwentyThousandDistinctTokensInLessThanASecond(): void
    {
        // Given
        $list = implode(' ', array_map(static fn (int $index): string => 'scope.' . $index, range(1, 20_000)));

        // When
        $start = hrtime(true);
        $scopes = Scope::parseList($list);
        $milliseconds = (hrtime(true) - $start) / 1_000_000;

        // Then
        static::assertCount(20_000, $scopes);
        static::assertLessThan(1_000, $milliseconds);
    }

    #[Test]
    public function aListOfOneTokenIsThatToken(): void
    {
        // When
        $scopes = Scope::parseList('openid');

        // Then
        static::assertCount(1, $scopes);
        static::assertTrue($scopes[0]->equals(Scope::openid()));
    }

    #[Test]
    #[DataProvider('provideInvalidLists')]
    public function itRejectsAListWithATokenThatIsNotOne(string $list): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('RFC 6749 §3.3');

        // When
        Scope::parseList($list);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidLists(): iterable
    {
        yield 'empty' => [''];
        yield 'two spaces make an empty token' => ['openid  profile'];
        yield 'a leading space' => [' openid'];
        yield 'a tab' => ["openid\tprofile"];
        yield 'a token beyond ASCII' => ['openid profilé'];
    }
}
