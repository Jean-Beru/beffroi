<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Oidc\Domain\Authorization\RequestObject;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidRequestObjectException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RequestObjectTest extends TestCase
{
    /**
     * OIDC Core §6.1: the claims of the object are the parameters of the request.
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
     * RFC 7519 §4.1: what the token says about itself is not a parameter of the request it carries.
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
     * OIDC Core §6.1: "max_age" as a number is what the field sends, and the query would have carried
     * its digits.
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
     * OIDC Core §5.5: "claims" is an object inside a request object, and the JSON the query would have
     * carried outside of it.
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
     * RFC 8707 §2.1: in a request object, a single "resource" is a JSON string and several are an array
     * of strings, which reaches the parser as the repeated parameter it is.
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
     * Decision 0006: a value no authorization request carries is refused, never cast into one.
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
        $this->expectExceptionMessageIsOrContains('The prompt claim of a request object is not a value an authorization request carries');

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
     * RFC 9101 §4: a request object carries the request, never another object.
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
