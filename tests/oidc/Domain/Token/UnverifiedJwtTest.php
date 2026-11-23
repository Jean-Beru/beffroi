<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UnverifiedJwtTest extends TestCase
{
    /**
     * RFC 7515 §4.1.1, §4.1.4
     */
    #[Test]
    public function itReadsTheAlgorithmAndTheKeyOfTheHeader(): void
    {
        // Given
        $jwt = new UnverifiedJwt(
            'the.compact.jws',
            [
                'alg' => 'ES256',
                'kid' => 'client-key',
            ],
            [],
        );

        // When / Then
        static::assertSame('ES256', $jwt->algorithm());
        static::assertSame('client-key', $jwt->keyId());
    }

    /**
     * @param array<string, mixed> $header
     */
    #[Test]
    #[DataProvider('provideHeadersThatNameNothing')]
    public function aHeaderThatNamesNoAlgorithmAndNoKeyNamesNone(array $header): void
    {
        // Given
        $jwt = new UnverifiedJwt('the.compact.jws', $header, []);

        // When / Then
        static::assertNull($jwt->algorithm());
        static::assertNull($jwt->keyId());
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideHeadersThatNameNothing(): iterable
    {
        yield 'an empty header' => [[]];
        yield 'empty strings' => [[
            'alg' => '',
            'kid' => '',
        ]];
        yield 'values that are not strings' => [[
            'alg' => 256,
            'kid' => ['client-key'],
        ]];
    }

    #[Test]
    public function aClaimIsTheTextItIsOrNothing(): void
    {
        // Given
        $jwt = new UnverifiedJwt(
            'the.compact.jws',
            [],
            [
                'iss' => 'oidc-demo',
                'sub' => '',
                'jti' => 42,
            ],
        );

        // When / Then
        static::assertSame('oidc-demo', $jwt->claim('iss'));
        static::assertNull($jwt->claim('sub'));
        static::assertNull($jwt->claim('jti'));
        static::assertNull($jwt->claim('aud'));
    }

    /**
     * RFC 7519 §2
     */
    #[Test]
    public function aNumericDateIsSecondsSinceTheEpochAndNothingElse(): void
    {
        // Given
        $jwt = new UnverifiedJwt(
            'the.compact.jws',
            [],
            [
                'exp' => 1_790_078_400,
                'iat' => '1790078400',
                'nbf' => 1_790_078_400.5,
            ],
        );

        // When / Then
        static::assertSame('2026-09-22T12:00:00+00:00', $jwt->time('exp')?->format('c'));
        static::assertNull($jwt->time('iat'));
        static::assertNull($jwt->time('nbf'));
        static::assertNull($jwt->time('auth_time'));
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideAudiences')]
    public function theAudienceIsOneStringOrAListOfThem(mixed $audience, array $expected): void
    {
        // Given
        $jwt = new UnverifiedJwt(
            'the.compact.jws',
            [],
            [
                'aud' => $audience,
            ],
        );

        // When / Then
        static::assertSame($expected, $jwt->audiences());
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function provideAudiences(): iterable
    {
        yield 'one string' => ['https://id.acme.example', ['https://id.acme.example']];
        yield 'a list of strings' => [
            ['https://id.acme.example', 'https://other.example'],
            ['https://id.acme.example', 'https://other.example'],
        ];
        yield 'a list naming one twice' => [
            ['https://id.acme.example', 'https://id.acme.example'],
            ['https://id.acme.example', 'https://id.acme.example'],
        ];
        yield 'nothing at all' => [null, []];
    }

    /**
     * RFC 7519 §4.1.3, decision 0016
     */
    #[Test]
    #[DataProvider('provideClaimsThatAreNotAnAudience')]
    public function anAudienceThatIsNeitherAStringNorAListOfThemNamesNone(mixed $audience): void
    {
        // Given
        $jwt = new UnverifiedJwt(
            'the.compact.jws',
            [],
            [
                'aud' => $audience,
            ],
        );

        // When / Then
        static::assertSame([], $jwt->audiences());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideClaimsThatAreNotAnAudience(): iterable
    {
        yield 'a list holding a number' => [['https://id.acme.example', 5]];
        yield 'a list holding a boolean and a null' => [['https://id.acme.example', true, null]];
        yield 'an object' => [
            [
                'x' => 'https://id.acme.example',
            ],
        ];
        yield 'a number' => [42];
    }

    /**
     * RFC 7519 §4.1.5
     *
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('provideStarts')]
    public function itStartsAtItsNotBefore(array $claims, bool $startsAfter): void
    {
        // Given
        $jwt = new UnverifiedJwt('the.compact.jws', [], $claims);

        // When / Then
        static::assertSame($startsAfter, $jwt->startsAfter(new DateTimeImmutable('@1790078400')));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideStarts(): iterable
    {
        yield 'no "nbf"' => [[], false];
        yield 'an "nbf" passed' => [
            [
                'nbf' => 1_790_078_399,
            ],
            false,
        ];
        yield 'an "nbf" at the instant' => [
            [
                'nbf' => 1_790_078_400,
            ],
            false,
        ];
        yield 'an "nbf" a second later' => [
            [
                'nbf' => 1_790_078_401,
            ],
            true,
        ];
        yield 'an "nbf" written as text' => [
            [
                'nbf' => '1790078399',
            ],
            true,
        ];
        yield 'an "nbf" with a fraction' => [
            [
                'nbf' => 1_790_078_399.5,
            ],
            true,
        ];
        yield 'a null "nbf"' => [
            [
                'nbf' => null,
            ],
            true,
        ];
    }

    #[Test]
    public function aTokenWithoutAnAudienceNamesNone(): void
    {
        // Given
        $jwt = new UnverifiedJwt('the.compact.jws', [], []);

        // When / Then
        static::assertSame([], $jwt->audiences());
    }
}
