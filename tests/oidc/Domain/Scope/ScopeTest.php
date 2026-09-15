<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Scope;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
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
}
