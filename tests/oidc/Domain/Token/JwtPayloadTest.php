<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Domain\Token\JwtPayload;
use JsonException;
use const NAN;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JwtPayloadTest extends TestCase
{
    /**
     * RFC 7519 §3: a JSON object; the text keeps UTF-8 and slashes as they are, a boolean stays a
     * boolean and a float stays a float, so that a client reads exactly the types the provider meant.
     */
    #[Test]
    public function itEncodesClaimsAsTheyAre(): void
    {
        static::assertSame('{"iss":"https://id.acme.example/t","name":"Zoé","email_verified":true,"score":1.0,"amr":["pwd"]}', JwtPayload::encode([
            'iss' => 'https://id.acme.example/t',
            'name' => 'Zoé',
            'email_verified' => true,
            'score' => 1.0,
            'amr' => ['pwd'],
        ]));
        static::assertSame('{}', JwtPayload::encode([]));
    }

    #[Test]
    public function aClaimThatCannotBeEncodedIsAProgrammingError(): void
    {
        $this->expectException(JsonException::class);

        JwtPayload::encode([
            'x' => NAN,
        ]);
    }
}
