<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Protocol\AuthorizationResponse;
use Beffroi\Tui\Protocol\ProviderRefusalException;
use Beffroi\Tui\Protocol\RejectedAnswerException;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The response the browser brings back is read issuer first, state second, and only then for what it says.
 */
final class AuthorizationResponseTest extends TestCase
{
    private const string STATE = 'drawn-state';

    #[Test]
    public function theCodeOfTheResponseOfThisProviderToThisRequestIsRead(): void
    {
        // Given
        $query = http_build_query(['code' => 'the-code', 'state' => self::STATE, 'iss' => FakeProvider::ISSUER]);

        // When / Then
        static::assertSame('the-code', AuthorizationResponse::codeOf($query, FakeProvider::ISSUER, self::STATE));
    }

    /**
     * RFC 9207 §2.4, RFC 6749 §10.12 and §3.1.
     */
    #[Test]
    #[DataProvider('provideResponsesThatAreNotTheAnswer')]
    public function aResponseThatIsNotTheAnswerToThisRequestIsRejected(string $query, string $reason): void
    {
        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        AuthorizationResponse::codeOf($query, FakeProvider::ISSUER, self::STATE);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideResponsesThatAreNotTheAnswer(): iterable
    {
        yield 'no issuer' => [http_build_query(['code' => 'c', 'state' => self::STATE]), 'names no issuer'];
        yield 'another issuer' => [http_build_query(['code' => 'c', 'state' => self::STATE, 'iss' => 'https://evil.example']), 'another issuer'];
        yield 'an issuer that only starts the same' => [
            http_build_query(['code' => 'c', 'state' => self::STATE, 'iss' => FakeProvider::ISSUER . '/']),
            'another issuer',
        ];
        yield 'no state' => [http_build_query(['code' => 'c', 'iss' => FakeProvider::ISSUER]), 'state of this request'];
        yield 'another state' => [http_build_query(['code' => 'c', 'state' => 'other', 'iss' => FakeProvider::ISSUER]), 'state of this request'];
        yield 'a refusal from elsewhere' => [
            http_build_query(['error' => 'access_denied', 'state' => self::STATE, 'iss' => 'https://evil.example']),
            'another issuer',
        ];
        yield 'a code written twice' => ['code=a&code=b&state=' . self::STATE . '&iss=' . FakeProvider::ISSUER, '"code" twice'];
        yield 'neither a code nor an error' => [http_build_query(['state' => self::STATE, 'iss' => FakeProvider::ISSUER]), 'neither a code nor an error'];
    }

    /**
     * RFC 6749 §4.1.2.1: the refusal of this provider to this request.
     */
    #[Test]
    public function theRefusalOfThisProviderIsItsRefusal(): void
    {
        // Given
        $query = http_build_query([
            'error' => 'unmet_authentication_requirements',
            'error_description' => 'Not a passkey.',
            'state' => self::STATE,
            'iss' => FakeProvider::ISSUER,
        ]);

        // When
        try {
            AuthorizationResponse::codeOf($query, FakeProvider::ISSUER, self::STATE);
            static::fail('The refusal is not read as one.');
        } catch (ProviderRefusalException $exception) {
            // Then
            static::assertSame(['unmet_authentication_requirements', 'Not a passkey.'], [$exception->error, $exception->description]);
        }
    }
}
