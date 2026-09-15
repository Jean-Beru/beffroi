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
    public function itIsAScopeToken(): void
    {
        static::assertSame('openid', (string) Scope::openid());
        static::assertSame('https://api.example/read', (string) new Scope('https://api.example/read'));
        static::assertSame('!#$%&\'()*+,-./:;<=>?@[]^_`{|}~', (string) new Scope('!#$%&\'()*+,-./:;<=>?@[]^_`{|}~'));
        static::assertTrue(Scope::openid()->equals(new Scope('openid')));
        static::assertFalse(Scope::openid()->equals(new Scope('OpenID')));
    }

    #[Test]
    #[DataProvider('provideInvalidScopes')]
    public function itRejectsWhatIsNotAScopeToken(string $scope): void
    {
        try {
            new Scope($scope);
            static::fail('The scope should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertStringContainsString('RFC 6749 §3.3', $exception->getMessage());
        }
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
