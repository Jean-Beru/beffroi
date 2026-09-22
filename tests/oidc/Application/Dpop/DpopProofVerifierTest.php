<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Dpop;

use DateTimeImmutable;
use Heidi\Oidc\Application\Dpop\DpopProofVerifier;
use Heidi\Oidc\Domain\Dpop\DpopProof;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use Heidi\Oidc\Exception\UseDpopNonceException;
use Heidi\Oidc\Tests\Fixture\FakeDpopNonce;
use Heidi\Oidc\Tests\Fixture\Proofs;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §4.3: what makes a proof a proof of this request, made by the holder of the key it carries.
 */
final class DpopProofVerifierTest extends TestCase
{
    private const string NOW = '2026-09-22T12:00:00+00:00';

    private const string ENDPOINT = 'https://id.acme.example/token';

    private DpopProofVerifier $verifier;

    protected function setUp(): void
    {
        $this->verifier = Proofs::verifier();
    }

    /**
     * RFC 9449 §6.1: what comes back is the key of the proof, named by its JWK thumbprint, which is
     * what a token is bound to.
     */
    #[Test]
    public function itAnswersTheKeyThatSignedTheProof(): void
    {
        // Given
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now());

        // When
        $key = $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());

        // Then
        static::assertEquals(Proofs::thumbprintOf(Proofs::key()), $key);
    }

    /**
     * A client that binds no token sends no proof, and nothing of this is asked of it.
     */
    #[Test]
    #[DataProvider('provideNoProof')]
    public function aRequestWithoutProofProvesNoKey(?string $header): void
    {
        // When / Then
        static::assertNull($this->verifier->verify($header, 'POST', self::ENDPOINT, $this->now()));
    }

    /**
     * RFC 9449 §4.3: the proof names the method and the endpoint of the request it was made for, and
     * the provider compares them with the endpoint it publishes, never with what a header of the
     * request says.
     */
    #[Test]
    #[DataProvider('provideOtherRequests')]
    public function aProofMadeForAnotherRequestIsRefused(string $method, string $url, string $description): void
    {
        // Given
        $proof = Proofs::proof($method, $url, $this->now());

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains($description);

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * RFC 9449 §4.3: the query and the fragment are no part of the endpoint a proof names.
     */
    #[Test]
    public function theQueryOfTheUrlIsNoPartOfWhatAProofNames(): void
    {
        // Given
        $proof = Proofs::proof('POST', self::ENDPOINT . '?tenant=acme#top', $this->now());

        // When
        $key = $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());

        // Then
        static::assertNotNull($key);
    }

    /**
     * RFC 9449 §11.1: a proof is used once. Whoever takes one off the wire and sends it again is
     * refused, however fresh it still is.
     */
    #[Test]
    public function aProofPresentedTwiceIsRefused(): void
    {
        // Given
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now());
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains('presented before');

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * RFC 9449 §4.3: a proof stands for the window the provider accepts, both ways.
     */
    #[Test]
    #[DataProvider('provideTimes')]
    public function aProofOutsideTheWindowIsRefused(string $made, string $description): void
    {
        // Given
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now()->modify($made));

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains($description);

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * The window is what is allowed of the clock of a client, and its edges are inside it: a proof made
     * exactly a leeway ahead, or exactly at the end of its life, is still this request's.
     */
    #[Test]
    #[DataProvider('provideEdgesOfTheWindow')]
    public function aProofOnTheEdgeOfTheWindowIsTaken(string $made): void
    {
        // Given
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now()->modify($made));

        // When
        $key = $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());

        // Then
        static::assertNotNull($key);
    }

    /**
     * RFC 9449 §7.1: a proof presented with an access token names that token, and a proof made for
     * another token does not open this one.
     */
    #[Test]
    public function aProofNamesTheAccessTokenItAccompanies(): void
    {
        // Given
        $proof = Proofs::proof('GET', self::ENDPOINT, $this->now(), 'the-access-token');

        // When
        $key = $this->verifier->verify($proof, 'GET', self::ENDPOINT, $this->now(), 'the-access-token');

        // Then
        static::assertNotNull($key);
    }

    #[Test]
    #[DataProvider('provideAccessTokens')]
    public function aProofMadeForAnotherAccessTokenIsRefused(?string $named, ?string $presented, string $description): void
    {
        // Given
        $proof = Proofs::proof('GET', self::ENDPOINT, $this->now(), $named);

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains($description);

        // When
        $this->verifier->verify($proof, 'GET', self::ENDPOINT, $this->now(), $presented);
    }

    /**
     * RFC 9449 §4.2: a proof carries what tells it from another JWT the same client signs (RFC 8725
     * §3.11), the claims of the section, and nothing else is read as one.
     */
    #[Test]
    #[DataProvider('provideMalformedProofs')]
    public function aProofThatIsNotOneIsRefused(string $proof, string $description): void
    {
        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains($description);

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * RFC 9449 §4.3: the signature is verified against the key of the header and against no other, so a
     * proof whose key is not the one that signed it proves nothing.
     */
    #[Test]
    public function aProofSignedByAnotherKeyThanTheOneItCarriesIsRefused(): void
    {
        // Given
        $proof = Proofs::proof(
            'POST',
            self::ENDPOINT,
            $this->now(),
            null,
            [],
            [
                DpopProof::KEY => Proofs::otherKey()->toPublic()->all(),
            ],
        );

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains('not signed by the key it carries');

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * RFC 9449 §4.3: a private key in the header is not a public key, and a provider that used the
     * public half of what a client sent by mistake would let that pass unsaid.
     */
    #[Test]
    public function aProofCarryingAPrivateKeyIsRefused(): void
    {
        // Given
        $proof = Proofs::proof(
            'POST',
            self::ENDPOINT,
            $this->now(),
            null,
            [],
            [
                DpopProof::KEY => Proofs::key()->all(),
            ],
        );

        // Then
        $this->expectException(InvalidDpopProofException::class);
        $this->expectExceptionMessageIsOrContains('not signed by the key it carries');

        // When
        $this->verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
    }

    /**
     * RFC 9449 §8: a provider that asks for a nonce hands one back with its refusal, and takes the
     * proof made again with it.
     */
    #[Test]
    public function aProofWithoutTheNonceTheProviderAsksForIsRefusedWithAFreshOne(): void
    {
        // Given
        $verifier = Proofs::verifier(new FakeDpopNonce('the-nonce'));
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now());

        // When
        try {
            $verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());
            static::fail('The proof should have been refused.');
        } catch (UseDpopNonceException $exception) {
            // Then
            static::assertSame('use_dpop_nonce', $exception->error);
            static::assertSame(400, $exception->statusCode, 'an endpoint that issues tokens answers the JSON of RFC 6749 section 5.2 (RFC 9449 section 8.1)');
            static::assertFalse($exception->redirectable);
            static::assertSame('the-nonce', $exception->nonce);
            static::assertSame(
                [
                    'DPoP-Nonce' => 'the-nonce',
                ],
                $exception->challengeHeaders(),
            );
        }
    }

    #[Test]
    public function aProofCarryingTheNonceIsTaken(): void
    {
        // Given
        $verifier = Proofs::verifier(new FakeDpopNonce('the-nonce'));
        $proof = Proofs::proof('POST', self::ENDPOINT, $this->now(), null, [
            'nonce' => 'the-nonce',
        ]);

        // When
        $key = $verifier->verify($proof, 'POST', self::ENDPOINT, $this->now());

        // Then
        static::assertNotNull($key);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideNoProof(): iterable
    {
        yield 'no header' => [null];
        yield 'an empty header' => [''];
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideOtherRequests(): iterable
    {
        yield 'another method' => ['GET', self::ENDPOINT, 'not the method of this request'];
        yield 'another endpoint' => ['POST', 'https://id.acme.example/par', 'not the endpoint this provider publishes'];
        yield 'another provider' => ['POST', 'https://id.attacker.example/token', 'not the endpoint this provider publishes'];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEdgesOfTheWindow(): iterable
    {
        yield 'made a whole leeway ahead' => ['+5 seconds'];
        yield 'made at the very end of its life' => ['-64 seconds'];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideTimes(): iterable
    {
        yield 'made at the very instant it stops standing' => ['-65 seconds', 'older than this provider accepts'];
        yield 'made long before' => ['-1 hour', 'older than this provider accepts'];
        yield 'made in the future' => ['+6 seconds', 'later than the request that carries it'];
    }

    /**
     * @return iterable<string, array{string|null, string|null, string}>
     */
    public static function provideAccessTokens(): iterable
    {
        yield 'another token' => ['another-access-token', 'the-access-token', 'not the access token this request presents'];
        yield 'no token named' => [null, 'the-access-token', 'names it in its ath'];
        yield 'a token named where none is presented' => ['the-access-token', null, 'names an access token this request does not present'];
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedProofs(): iterable
    {
        $now = new DateTimeImmutable(self::NOW);

        yield 'not a JWT at all' => ['not-a-jwt', 'not a readable JWT'];
        yield 'another type' => [
            Proofs::proof(
                'POST',
                self::ENDPOINT,
                $now,
                null,
                [],
                [
                    'typ' => 'jwt',
                ],
            ),
            'is a JWT of type dpop+jwt',
        ];
        yield 'no jti' => [Proofs::proof('POST', self::ENDPOINT, $now, null, [
                'jti' => null,
            ]), 'carries a jti'];
        yield 'no htm' => [Proofs::proof('POST', self::ENDPOINT, $now, null, [
                'htm' => null,
            ]), 'carries a htm'];
        yield 'no htu' => [Proofs::proof('POST', self::ENDPOINT, $now, null, [
                'htu' => null,
            ]), 'carries a htu'];
        yield 'no iat' => [Proofs::proof('POST', self::ENDPOINT, $now, null, [
                'iat' => null,
            ]), 'carries an iat'];
        yield 'an iat that is not a number' => [Proofs::proof('POST', self::ENDPOINT, $now, null, [
                'iat' => 'now',
            ]), 'carries an iat'];
        yield 'no key in the header' => [
            Proofs::proof(
                'POST',
                self::ENDPOINT,
                $now,
                null,
                [],
                [
                    DpopProof::KEY => null,
                ],
            ),
            'not signed by the key it carries',
        ];
        yield 'a key that is not one' => [
            Proofs::proof(
                'POST',
                self::ENDPOINT,
                $now,
                null,
                [],
                [
                    DpopProof::KEY => 'a-key',
                ],
            ),
            'not signed by the key it carries',
        ];
    }

    private function now(): DateTimeImmutable
    {
        return new DateTimeImmutable(self::NOW);
    }
}
