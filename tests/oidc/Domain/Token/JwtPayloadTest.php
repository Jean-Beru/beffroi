<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use JsonException;
use const NAN;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JwtPayloadTest extends TestCase
{
    /**
     * RFC 7519 §3
     */
    #[Test]
    public function itEncodesClaimsAsTheyAre(): void
    {
        // When
        $json = JwtPayload::encode([
            'iss' => 'https://id.acme.example/t',
            'name' => 'Zoé',
            'email_verified' => true,
            'score' => 1.0,
            'amr' => ['pwd'],
        ]);

        // Then
        static::assertSame('{"iss":"https://id.acme.example/t","name":"Zoé","email_verified":true,"score":1.0,"amr":["pwd"]}', $json);
    }

    #[Test]
    public function noClaimIsAnEmptyObject(): void
    {
        // When / Then
        static::assertSame('{}', JwtPayload::encode([]));
    }

    #[Test]
    public function aClaimThatCannotBeEncodedIsAProgrammingError(): void
    {
        // Then
        $this->expectException(JsonException::class);

        // When
        JwtPayload::encode([
            'x' => NAN,
        ]);
    }

    /**
     * RFC 7519 §7.2
     */
    #[Test]
    public function itDecodesTheClaimsOfAPayload(): void
    {
        // When
        $claims = JwtPayload::decode('{"iss":"https://id.acme.example/t","aud":["a","b"],"exp":1}', 4);

        // Then
        static::assertSame(
            [
                'iss' => 'https://id.acme.example/t',
                'aud' => ['a', 'b'],
                'exp' => 1,
            ],
            $claims,
        );
    }

    /**
     * RFC 7519 §7.2
     */
    #[Test]
    #[DataProvider('providePayloadsThatAreNoObject')]
    public function aPayloadThatIsNoJsonObjectIsNoClaimsSet(string $payload): void
    {
        // When / Then
        static::assertNull(JwtPayload::decode($payload, 4));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePayloadsThatAreNoObject(): iterable
    {
        yield 'an array' => ['["https://id.acme.example/t"]'];
        yield 'an array of an object' => ['[{"iss":"https://id.acme.example/t"}]'];
        yield 'a string' => ['"https://id.acme.example/t"'];
        yield 'a number' => ['1'];
        yield 'null' => ['null'];
    }

    /**
     * RFC 7519 §4.1.3, decision 0016
     */
    #[Test]
    #[DataProvider('provideAudiencesThatAreObjects')]
    public function anAudThatIsAJsonObjectNamesNoAudience(string $payload): void
    {
        // Given
        $claims = JwtPayload::decode($payload, 4);

        // When / Then
        static::assertNull(TokenAudience::valuesOf($claims['aud'] ?? null));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAudiencesThatAreObjects(): iterable
    {
        yield 'one audience under the key 0' => ['{"aud":{"0":"https://id.acme.example/t"}}'];
        yield 'two audiences under the keys 0 and 1' => ['{"aud":{"0":"https://id.acme.example/t","1":"https://other.example"}}'];
        yield 'no member' => ['{"aud":{}}'];
    }

    #[Test]
    public function aPayloadDeeperThanItsBoundIsRefused(): void
    {
        // Then
        $this->expectException(JsonException::class);

        // When
        JwtPayload::decode('{"address":{"street":{"number":1}}}', 2);
    }
}
