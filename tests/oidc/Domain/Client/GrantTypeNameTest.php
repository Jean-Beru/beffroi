<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 appendix A.10: a grant type is a name of the registry or the absolute URI of an extension
 * grant (§4.5, RFC 6755). The value object carries that shape and never a list of the names that exist.
 */
final class GrantTypeNameTest extends TestCase
{
    #[Test]
    #[DataProvider('provideNames')]
    public function itTakesTheNameOfAnyGrantOfTheSpecifications(string $name): void
    {
        // When / Then
        static::assertSame($name, new GrantTypeName($name)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNames(): iterable
    {
        yield 'authorization_code' => ['authorization_code'];
        yield 'refresh_token' => ['refresh_token'];
        yield 'client_credentials' => ['client_credentials'];
        yield 'device_code, a URN (RFC 8628 §3.4)' => ['urn:ietf:params:oauth:grant-type:device_code'];
        yield 'jwt-bearer, a URN (RFC 7523 §2.1)' => ['urn:ietf:params:oauth:grant-type:jwt-bearer'];
        yield 'token-exchange, a URN (RFC 8693 §2.1)' => ['urn:ietf:params:oauth:grant-type:token-exchange'];
        yield 'an https URI (RFC 6749 §4.5)' => ['https://example.com/grants/invented'];
    }

    #[Test]
    #[DataProvider('provideNamesOfNoShape')]
    public function itRefusesWhatNamesNoGrant(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('names no grant');

        // When
        new GrantTypeName($name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesOfNoShape(): iterable
    {
        yield 'empty' => [''];
        yield 'a space' => ['authorization code'];
        yield 'a colon with nothing after it' => ['urn:'];
        yield 'a fragment' => ['https://example.com/grants#invented'];
        yield 'a relative reference' => ['/grants/invented'];
        yield 'a line feed behind a name of the registry' => ["authorization_code\n"];
        yield 'a line feed behind an absolute URI' => ["urn:ietf:params:oauth:grant-type:device_code\n"];
    }

    /**
     * RFC 6749 §4.1.3: the "grant_type" of a request is compared byte for byte, so a name in another
     * case names another grant.
     */
    #[Test]
    public function aNameIsComparedByteForByte(): void
    {
        // Given
        $grantType = new GrantTypeName('authorization_code');

        // When / Then
        static::assertTrue($grantType->equals(new GrantTypeName('authorization_code')));
        static::assertFalse($grantType->equals(new GrantTypeName('Authorization_Code')));
    }
}
