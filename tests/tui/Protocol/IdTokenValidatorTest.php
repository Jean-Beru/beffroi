<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Protocol\Identity;
use Beffroi\Tui\Protocol\IdTokenValidator;
use Beffroi\Tui\Protocol\RejectedAnswerException;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use DateTimeImmutable;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * OIDC Core §3.1.3.7: nothing in the ID token names the administrator before every rule holds.
 */
final class IdTokenValidatorTest extends TestCase
{
    private const string NONCE = 'drawn-nonce';

    private FakeProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new FakeProvider();
    }

    #[Test]
    public function theIdentityOfAValidTokenIsRead(): void
    {
        // Given
        $idToken = $this->provider->idToken(FakeProvider::claims(self::NONCE, ['name' => 'Ada']));

        // When
        $identity = $this->validate($idToken);

        // Then
        static::assertSame(
            ['administrator', 'phr', ['hwk', 'user'], FakeProvider::NOW - 10, 'Ada'],
            [$identity->subject, $identity->authenticationClass, $identity->methods, $identity->authenticatedAt, $identity->name],
        );
    }

    /**
     * EAP ACR Values 1.0: the hardware-bound class is the phishing-resistant one and more.
     */
    #[Test]
    public function theHardwareBoundClassIsPhishingResistant(): void
    {
        // When
        $identity = $this->validate($this->provider->idToken(FakeProvider::claims(self::NONCE, ['acr' => 'phrh'])));

        // Then
        static::assertSame('phrh', $identity->authenticationClass);
    }

    /**
     * @param array<string, mixed> $replacing
     */
    #[Test]
    #[DataProvider('provideClaimsThatDoNotHold')]
    public function aTokenWhoseClaimsDoNotHoldIsRejected(array $replacing, string $reason): void
    {
        // Given
        $idToken = $this->provider->idToken(FakeProvider::claims(self::NONCE, $replacing));

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->validate($idToken);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideClaimsThatDoNotHold(): iterable
    {
        yield 'another issuer (item 2)' => [['iss' => 'https://evil.example'], 'another issuer'];
        yield 'another audience (item 3)' => [['aud' => 'another-client'], 'another audience'];
        yield 'an audience this client does not trust beside it (item 3)' => [['aud' => [FakeProvider::CLIENT_ID, 'another-client']], 'another audience'];
        yield 'another authorized party (item 5)' => [['azp' => 'another-client'], 'another party'];
        yield 'expired a minute and a second ago (item 9)' => [['exp' => FakeProvider::NOW - 61], 'expired'];
        yield 'no expiry' => [['exp' => null], '"exp"'];
        yield 'issued in the future (item 10)' => [['iat' => FakeProvider::NOW + 61], 'in the future'];
        yield 'another nonce (item 11)' => [['nonce' => 'replayed'], 'nonce of this request'];
        yield 'no nonce (item 11)' => [['nonce' => null], 'nonce of this request'];
        yield 'a password login (decision 0038)' => [['acr' => '1'], 'phishing-resistant proof'];
        yield 'no class at all (item 12)' => [['acr' => null], 'phishing-resistant proof'];
    }

    /**
     * OIDC Core §3.1.3.7, items 6 and 7.
     *
     * @param array<string, mixed> $header
     */
    #[Test]
    #[DataProvider('provideSignaturesThatDoNotHold')]
    public function aTokenWhoseSignatureDoesNotHoldIsRejected(bool $signedByAnotherKey, array $header, string $reason): void
    {
        // Given
        $idToken = $this->provider->idToken(
            FakeProvider::claims(self::NONCE),
            $signedByAnotherKey ? JWKFactory::createECKey('P-256', ['kid' => FakeProvider::KEY_ID]) : null,
            $header,
        );

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->validate($idToken);
    }

    /**
     * @return iterable<string, array{bool, array<string, mixed>, string}>
     */
    public static function provideSignaturesThatDoNotHold(): iterable
    {
        yield 'a key that claims the name of the provider\'s' => [true, [], 'does not verify'];
        yield 'a key the provider does not publish' => [false, ['kid' => 'unknown'], 'does not publish'];
        yield 'the encryption key of the provider' => [false, ['kid' => 'encryption-key'], 'does not publish'];
        yield 'a parameter it must be understood by (RFC 7515 §4.1.11)' => [false, ['crit' => ['exp'], 'exp' => 1], 'must be understood by'];
    }

    /**
     * OIDC Core §3.1.3.7, item 7: the algorithm this client registered, and no other the provider could use.
     */
    #[Test]
    public function aTokenSignedWithAnotherAlgorithmThanTheRegisteredOneIsRejected(): void
    {
        // Given
        $idToken = $this->provider->idToken(FakeProvider::claims(self::NONCE));

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIs('The ID token is signed with "ES256" and this client registered "PS256" (OIDC Core §3.1.3.7, item 7).');

        // When
        $this->validate($idToken, 'PS256');
    }

    /**
     * FAPI 2.0 Security Profile §5.4.1: an RSA key of 2048 bits at least, whatever it signed.
     */
    #[Test]
    public function aTokenSignedByAnRsaKeyOfFewerThan2048BitsIsRejected(): void
    {
        // Given
        $weak = JWKFactory::createRSAKey(1024, ['kid' => 'weak-key', 'alg' => 'PS256', 'use' => 'sig']);
        $idToken = $this->provider->idToken(FakeProvider::claims(self::NONCE), $weak, ['alg' => 'PS256', 'kid' => 'weak-key']);

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIs('The ID token is signed by an RSA key of fewer than 2048 bits (FAPI 2.0 Security Profile §5.4.1).');

        // When
        $this->validate($idToken, 'PS256', [$weak]);
    }

    #[Test]
    public function aTokenSignedByAnRsaKeyOf2048BitsIsRead(): void
    {
        // Given
        $key = JWKFactory::createRSAKey(2048, ['kid' => 'rsa-key', 'alg' => 'PS256', 'use' => 'sig']);
        $idToken = $this->provider->idToken(FakeProvider::claims(self::NONCE), $key, ['alg' => 'PS256', 'kid' => 'rsa-key']);

        // When
        $identity = $this->validate($idToken, 'PS256', [$key]);

        // Then
        static::assertSame('administrator', $identity->subject);
    }

    #[Test]
    public function anEncryptedTokenIsRejected(): void
    {
        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIs('The ID token is not a signed JWT in the compact serialization (OIDC Core §2).');

        // When
        $this->validate('eyJhbGciOiJFQ0RILUVTIn0.a.b.c.d');
    }

    /**
     * @param list<JWK> $published the keys the provider publishes beside its own
     */
    private function validate(string $idToken, string $algorithm = 'ES256', array $published = []): Identity
    {
        $http = new MockHttpClient(new MockResponse($this->provider->jwks($published)));

        return new IdTokenValidator($http, new MockClock(new DateTimeImmutable('@' . FakeProvider::NOW)))->validate(
            $idToken,
            FakeProvider::metadata(),
            FakeProvider::CLIENT_ID,
            $algorithm,
            self::NONCE,
        );
    }
}
