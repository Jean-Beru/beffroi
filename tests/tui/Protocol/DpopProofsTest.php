<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\DpopProofs;
use Beffroi\Tui\Tests\Fixture\Jwt;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * RFC 9449: one proof per request, signed by the key of the run, and the nonce each server handed out.
 */
final class DpopProofsTest extends TestCase
{
    /**
     * RFC 9449 §4.2: the type of a proof and the public key it is verified with, which carries nothing private.
     */
    #[Test]
    public function aProofCarriesItsTypeAndThePublicKeyItIsVerifiedWith(): void
    {
        // Given
        $key = SigningKey::generate();

        // When
        $header = Jwt::header(new DpopProofs($key, new MockClock())->proof('POST', 'https://op.example/token'))->members;

        // Then
        static::assertSame(['dpop+jwt', $key->publicJwk()], [$header['typ'] ?? null, $header['jwk'] ?? null]);
    }

    /**
     * RFC 9449 §4.2: "htu" is the URI of the request without its query and its fragment.
     */
    #[Test]
    public function aProofNamesTheUriWithoutItsQueryAndItsFragment(): void
    {
        // When
        $claims = Jwt::claims(new DpopProofs(SigningKey::generate(), new MockClock())->proof('GET', 'https://api.example/users?page=2#top'))->members;

        // Then
        static::assertSame(['GET', 'https://api.example/users'], [$claims['htm'] ?? null, $claims['htu'] ?? null]);
    }

    /**
     * RFC 9449 §4.2, §7.1: "ath" is the base64url SHA-256 of the access token the proof goes with.
     */
    #[Test]
    public function aProofForAResourceCarriesTheHashOfTheAccessToken(): void
    {
        // When
        $claims = Jwt::claims(new DpopProofs(SigningKey::generate(), new MockClock())->proof(
            'GET',
            'https://op.example/userinfo',
            'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU',
        ))->members;

        // Then
        static::assertSame('fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo', $claims['ath'] ?? null);
    }

    /**
     * RFC 9449 §8.2, §9: the nonce a server answered goes into the next proof sent to it, and to no other server.
     */
    #[Test]
    #[DataProvider('provideWhereTheNextProofGoes')]
    public function theNonceOfAServerGoesToThatServerAlone(string $uri, ?string $nonce): void
    {
        // Given
        $proofs = new DpopProofs(SigningKey::generate(), new MockClock());
        $proofs->remember('https://op.example/token', new MockHttpClient(new MockResponse('', ['response_headers' => [
            'DPoP-Nonce' => 'eyJ7S_zG.eyJH0-Z.HX4w-7v',
        ]]))->request('POST', 'https://op.example/token'));

        // When
        $claims = Jwt::claims($proofs->proof('POST', $uri))->members;

        // Then
        static::assertSame($nonce, $claims['nonce'] ?? null);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideWhereTheNextProofGoes(): iterable
    {
        yield 'the same server' => ['https://op.example/par', 'eyJ7S_zG.eyJH0-Z.HX4w-7v'];
        yield 'another host' => ['https://api.example/users', null];
        yield 'another port' => ['https://op.example:8443/token', null];
    }

    /**
     * RFC 9449 §8.1: a nonce is `1*NQCHAR`, and a header that holds anything else carries none.
     */
    #[Test]
    public function aNonceThatIsNoNqcharStringIsNotKept(): void
    {
        // Given
        $proofs = new DpopProofs(SigningKey::generate(), new MockClock());
        $proofs->remember('https://op.example/token', new MockHttpClient(new MockResponse('', ['response_headers' => [
            'DPoP-Nonce' => 'two words',
        ]]))->request('POST', 'https://op.example/token'));

        // When
        $claims = Jwt::claims($proofs->proof('POST', 'https://op.example/token'))->members;

        // Then
        static::assertArrayNotHasKey('nonce', $claims);
    }
}
