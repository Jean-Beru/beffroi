<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Profiler;

use App\Profiler\WithheldValues;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class WithheldValuesTest extends TestCase
{
    /**
     * RFC 6749 §1.4, §1.5, OIDC Core §3.1.2.1, RFC 8628 §3.2, §3.3.1, §5.1, §5.2, CIBA Core §7.1, §7.3,
     * RFC 9126 §2.2, §7.1
     */
    #[Test]
    #[DataProvider('provideNamesThatHandOverWhatTheyName')]
    public function aNameThatHandsOverWhatItNamesIsWithheld(string $name): void
    {
        // When / Then
        static::assertTrue(WithheldValues::withholds($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatHandOverWhatTheyName(): iterable
    {
        yield 'an access token' => ['access_token'];
        yield 'a refresh token' => ['refresh_token'];
        yield 'an ID token handed back as a hint' => ['id_token_hint'];
        yield 'an authorization code' => ['code'];
        yield 'a verifier' => ['code_verifier'];
        yield 'a client secret' => ['client_secret'];
        yield 'a client assertion' => ['client_assertion'];
        yield 'a request object' => ['request'];
        yield 'a proof of possession' => ['dpop'];
        yield 'the device code' => ['device_code'];
        yield 'the user code' => ['user_code'];
        yield 'the verification URI that carries the user code' => ['verification_uri_complete'];
        yield 'the identifier of a backchannel request' => ['auth_req_id'];
        yield 'the reference of a pushed request' => ['request_uri'];
    }

    /**
     * RFC 8628 §3.2, CIBA Core §7.3, RFC 9126 §2.2
     */
    #[Test]
    #[DataProvider('provideNamesThatHandOverNothing')]
    public function aNameThatHandsOverNothingIsWrittenAsItIs(string $name): void
    {
        // When / Then
        static::assertFalse(WithheldValues::withholds($name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatHandOverNothing(): iterable
    {
        yield 'the page where the user types the code' => ['verification_uri'];
        yield 'a lifetime' => ['expires_in'];
        yield 'a polling interval' => ['interval'];
    }
}
