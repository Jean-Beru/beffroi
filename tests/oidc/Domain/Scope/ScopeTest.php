<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Scope;

use function array_map;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ScopeTest extends TestCase
{
    /**
     * RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
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
     * OIDC Core §11.
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
    }

    /**
     * RFC 6749 §3.3: space-delimited, case-sensitive.
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
