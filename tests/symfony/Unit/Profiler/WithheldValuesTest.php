<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Profiler;

use App\Profiler\WithheldValues;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Which named values of the protocol the panel says are there and never writes: the ones whose holder holds
 * what they name, wherever they are written.
 */
final class WithheldValuesTest extends TestCase
{
    /**
     * RFC 6749 §1.4 and §1.5, OIDC Core §3.1.2.1, and what stands for a request in progress: the two codes of
     * the device grant (RFC 8628 §3.2), both worth guessing (§5.1, §5.2), the verification URI that carries
     * the user code (§3.3.1), the identifier of a backchannel request (CIBA Core §7.3) and the reference of a
     * pushed request (RFC 9126 §2.2, §7.1). "user_code" is also the secret of the user a backchannel request
     * may carry (CIBA Core §7.1).
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
     * RFC 8628 §3.2, CIBA Core §7.3, RFC 9126 §2.2: what the same answers say beside a code, an identifier or
     * a reference is written as it is, the page where the user types the code included.
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
