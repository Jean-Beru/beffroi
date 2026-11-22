<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RequestObjectTest extends TestCase
{
    /**
     * OIDC Core §6.1
     */
    #[Test]
    public function theClaimsOfTheObjectAreTheParametersOfTheRequest(): void
    {
        // Given
        $object = self::objectOf([
            'response_type' => 'code',
            'client_id' => 'oidc-demo',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'scope' => 'openid profile',
            'state' => 'af0ifjsldkj',
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'response_type' => 'code',
                'client_id' => 'oidc-demo',
                'redirect_uri' => 'https://demo.localhost/login/check',
                'scope' => 'openid profile',
                'state' => 'af0ifjsldkj',
            ],
            $parameters,
        );
    }

    /**
     * RFC 7519 §4.1
     */
    #[Test]
    public function theClaimsAJwtMakesAboutItselfAreNoParameters(): void
    {
        // Given
        $object = self::objectOf([
            'iss' => 'oidc-demo',
            'aud' => 'https://id.acme.example',
            'exp' => 1_790_000_060,
            'nbf' => 1_790_000_000,
            'iat' => 1_790_000_000,
            'jti' => 'once',
            'scope' => 'openid',
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'scope' => 'openid',
            ],
            $parameters,
        );
    }

    /**
     * OIDC Core §6.1
     */
    #[Test]
    public function aNumberIsReadAsTheParameterTheQueryWouldHaveCarried(): void
    {
        // Given
        $object = self::objectOf([
            'max_age' => 86400,
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'max_age' => '86400',
            ],
            $parameters,
        );
    }

    /**
     * OIDC Core §5.5
     */
    #[Test]
    public function anObjectIsReadAsTheJsonTheQueryWouldHaveCarried(): void
    {
        // Given
        $object = self::objectOf([
            'claims' => [
                'id_token' => [
                    'acr' => [
                        'essential' => true,
                    ],
                ],
            ],
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'claims' => '{"id_token":{"acr":{"essential":true}}}',
            ],
            $parameters,
        );
    }

    /**
     * RFC 8707 §2.1
     */
    #[Test]
    public function aListOfStringsIsAParameterGivenSeveralValues(): void
    {
        // Given
        $object = self::objectOf([
            'resource' => ['https://cal.example.com/', 'https://contacts.example.com/'],
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'resource' => ['https://cal.example.com/', 'https://contacts.example.com/'],
            ],
            $parameters,
        );
    }

    /**
     * OIDC Core §6.1
     *
     * @param array<array-key, mixed> $value
     */
    #[Test]
    #[DataProvider('provideArraysThatAreNotSeveralValues')]
    public function anArrayThatIsNotAListOfStringsIsWrittenBackAsJson(array $value, string $json): void
    {
        // Given
        $object = self::objectOf([
            'resource' => $value,
        ]);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'resource' => $json,
            ],
            $parameters,
        );
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideArraysThatAreNotSeveralValues(): iterable
    {
        yield 'a list holding a number' => [['https://cal.example.com/', 1], '["https://cal.example.com/",1]'];
        yield 'an object of strings' => [
            [
                'one' => 'https://cal.example.com/',
            ],
            '{"one":"https://cal.example.com/"}',
        ];
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideValuesNoRequestCarries')]
    public function aValueNoRequestCarriesIsRefused(mixed $value): void
    {
        // Given
        $object = self::objectOf([
            'prompt' => $value,
        ]);

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIsOrContains('A claim of the request object holds a value no authorization request carries');

        // When
        $object->parameters();
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideValuesNoRequestCarries(): iterable
    {
        yield 'a boolean' => [true];
        yield 'a fraction' => [1.5];
        yield 'null' => [null];
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    #[DataProvider('provideNamesNoDescriptionCarries')]
    public function theRefusalOfAValueNamesNoClaim(string $name): void
    {
        // Given
        $object = self::objectOf([
            $name => true,
        ]);

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIs('invalid_request_object: A claim of the request object holds a value no authorization request carries (OIDC Core section 6.1).');

        // When
        $object->parameters();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesNoDescriptionCarries(): iterable
    {
        yield 'a double quote' => ['pro"mpt'];
        yield 'a backslash' => ['pro\\mpt'];
        yield 'a line feed' => ["pro\nmpt"];
        yield 'a character outside ASCII' => ['prömpt'];
    }

    /**
     * RFC 9101 §4
     */
    #[Test]
    #[DataProvider('provideNestedParameters')]
    public function anObjectInsideAnObjectIsRefused(string $name): void
    {
        // Given
        $object = self::objectOf([
            $name => 'https://client.example/request.jwt',
        ]);

        // Then
        $this->expectException(InvalidRequestObjectException::class);
        $this->expectExceptionMessageIsOrContains('carries no ' . $name . ' parameter of its own');

        // When
        $object->parameters();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNestedParameters(): iterable
    {
        yield 'request' => ['request'];
        yield 'request_uri' => ['request_uri'];
    }

    /**
     * RFC 9101 §4, RFC 6749 §3.1
     */
    #[Test]
    #[DataProvider('provideClaimsNamedByANumber')]
    public function aClaimNamedByANumberIsIgnored(string $json): void
    {
        // Given
        $object = self::objectOfJson($json);

        // When
        $parameters = $object->parameters();

        // Then
        static::assertSame(
            [
                'scope' => 'openid',
            ],
            $parameters,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClaimsNamedByANumber(): iterable
    {
        yield 'digits' => ['{"scope":"openid","123":"x"}'];
        yield 'zero' => ['{"scope":"openid","0":"x"}'];
        yield 'a negative number' => ['{"scope":"openid","-1":"x"}'];
        yield 'a value no request carries' => ['{"scope":"openid","123":true}'];
    }

    private static function objectOfJson(string $json): RequestObject
    {
        $claims = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        static::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return self::objectOf($claims);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function objectOf(array $claims): RequestObject
    {
        return new RequestObject(
            new UnverifiedJwt(
                'the.compact.jws',
                [
                    'alg' => 'ES256',
                ],
                $claims,
            ),
        );
    }
}
