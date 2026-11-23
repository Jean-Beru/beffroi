<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\JwtLibrary;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Exception\InvalidJwtException;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JwtLibraryCompactJwtReaderTest extends TestCase
{
    private const string CLAIMS = '{"iss":"a-client","sub":"a-client"}';

    /**
     * RFC 7515 §4.1.11, RFC 7797 §6
     */
    #[Test]
    #[DataProvider('provideTokensThatUseAnExtension')]
    public function aTokenThatUsesAnExtensionOfJoseIsRefused(string $jwt): void
    {
        // Then
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessageIs('The token uses an extension of JOSE this provider does not understand (RFC 7515 section 4.1.11).');

        // When
        new JwtLibraryCompactJwtReader()->read($jwt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTokensThatUseAnExtension(): iterable
    {
        yield 'a critical parameter' => [self::compact([
            'alg' => 'ES256',
            'crit' => ['urn:example:must-understand'],
            'urn:example:must-understand' => true,
        ], Base64Url::encode(self::CLAIMS))];
        yield 'an unencoded payload not named critical' => [self::compact([
            'alg' => 'ES256',
            'b64' => false,
        ], self::CLAIMS)];
        yield 'an unencoded payload named critical' => [self::compact([
            'alg' => 'ES256',
            'b64' => false,
            'crit' => ['b64'],
        ], self::CLAIMS)];
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function compact(array $header, string $payload): string
    {
        return Base64Url::encode(json_encode($header, JSON_THROW_ON_ERROR)) . '.' . $payload . '.' . Base64Url::encode('signature');
    }
}
