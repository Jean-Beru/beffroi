<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UnverifiedJwtTest extends TestCase
{
    /**
     * RFC 7515 §4.1.1 and §4.1.4: what the protected header says of the signature, read as it is.
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
     * A header that names neither names none: nothing is guessed and nothing is cast.
     *
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

    /**
     * A claim is read when it is the text it is supposed to be, and read as absent otherwise.
     */
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
     * RFC 7519 §2: a numeric date is a number of seconds since the epoch, and nothing else is read as one.
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
     * RFC 7519 §4.1.3: one string, or an array of them.
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
        yield 'a list with something that is not a string' => [['https://id.acme.example', 42], ['https://id.acme.example']];
        yield 'nothing at all' => [null, []];
    }

    /**
     * An audience nobody set is no audience.
     */
    #[Test]
    public function aTokenWithoutAnAudienceNamesNone(): void
    {
        // Given
        $jwt = new UnverifiedJwt('the.compact.jws', [], []);

        // When / Then
        static::assertSame([], $jwt->audiences());
    }
}
