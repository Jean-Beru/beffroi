<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Protocol\AuthenticationChallenge;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9110 §11.2, §5.6.4: a parameter of a challenge is a token or a quoted string, and a quoted string is unquoted.
 */
final class AuthenticationChallengeTest extends TestCase
{
    #[Test]
    #[DataProvider('provideChallenges')]
    public function aParameterIsReadAsTheChallengeWritesIt(string $challenges, string $name, ?string $value): void
    {
        // When / Then
        static::assertSame($value, AuthenticationChallenge::parameter($challenges, $name));
    }

    /**
     * @return iterable<string, array{string, string, ?string}>
     */
    public static function provideChallenges(): iterable
    {
        yield 'a quoted string' => ['DPoP error="invalid_token"', 'error', 'invalid_token'];
        yield 'a token' => ['DPoP error=invalid_token', 'error', 'invalid_token'];
        yield 'a quoted pair' => [
            'DPoP error="invalid_token", error_description="The \"htu\" does not match."',
            'error_description',
            'The "htu" does not match.',
        ];
        yield 'a comma in a quoted string' => ['DPoP error_description="Expired, refresh it."', 'error_description', 'Expired, refresh it.'];
        yield 'a parameter is not another one it begins' => ['DPoP error_description="It expired."', 'error', null];
        yield 'the first challenge that carries it' => ['Bearer realm="admin", DPoP algs="ES256", error="use_dpop_nonce"', 'error', 'use_dpop_nonce'];
        yield 'blanks around the sign' => ['DPoP error = "invalid_token"', 'error', 'invalid_token'];
        yield 'no challenge' => ['', 'error', null];
    }
}
