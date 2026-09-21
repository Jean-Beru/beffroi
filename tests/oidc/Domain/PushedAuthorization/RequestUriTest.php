<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\PushedAuthorization;

use function hash;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;

final class RequestUriTest extends TestCase
{
    /**
     * RFC 9126 §2.2: the URN the specification registers, with the reference behind it.
     */
    #[Test]
    public function aGeneratedReferenceIsTheUrnOfTheSpecification(): void
    {
        // When
        $requestUri = RequestUri::generate();

        // Then
        static::assertStringStartsWith('urn:ietf:params:oauth:request_uri:', $requestUri->value);
        static::assertSame(strlen(RequestUri::URN_PREFIX) + 43, strlen($requestUri->value));
    }

    /**
     * RFC 9126 §7.1: the reference is guessed by nobody, which is 256 bits of randomness and a value no
     * two calls share.
     */
    #[Test]
    public function twoGeneratedReferencesDiffer(): void
    {
        // When
        $first = RequestUri::generate();
        $second = RequestUri::generate();

        // Then
        static::assertNotSame($first->value, $second->value);
    }

    #[Test]
    public function aGeneratedReferenceIsOneOfOurs(): void
    {
        // When / Then
        static::assertTrue(RequestUri::isOurs(RequestUri::generate()->value));
    }

    /**
     * OIDC Core §6.2: a "request_uri" that is not one of ours is a request object by reference, which
     * the authorization endpoint answers for; nothing here looks it up and nothing fetches it.
     */
    #[Test]
    #[DataProvider('provideForeignReferences')]
    public function aReferenceOfAnotherShapeIsNotOurs(string $value): void
    {
        // When / Then
        static::assertFalse(RequestUri::isOurs($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideForeignReferences(): iterable
    {
        yield 'empty' => [''];
        yield 'an https URL, which is how a request object is referenced' => ['https://client.example/request.jwt'];
        yield 'the prefix alone' => ['urn:ietf:params:oauth:request_uri:'];
        yield 'another URN' => ['urn:ietf:params:oauth:token-type:jwt'];
        yield 'too short' => ['urn:ietf:params:oauth:request_uri:' . str_repeat('a', 42)];
        yield 'too long' => ['urn:ietf:params:oauth:request_uri:' . str_repeat('a', 44)];
        yield 'not base64url' => ['urn:ietf:params:oauth:request_uri:' . str_repeat('a', 42) . '+'];
        yield 'a newline behind a reference that would pass' => ['urn:ietf:params:oauth:request_uri:' . str_repeat('a', 43) . "\n"];
    }

    /**
     * The store keeps the SHA-256 and never the value, as it keeps an authorization code.
     */
    #[Test]
    public function theHashIsTheSha256OfTheValue(): void
    {
        // Given
        $requestUri = RequestUri::generate();

        // When / Then
        static::assertSame(hash('sha256', $requestUri->value), $requestUri->hash());
    }
}
