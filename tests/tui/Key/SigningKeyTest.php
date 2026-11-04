<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Key;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Json\UnreadableDocumentException;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Tests\Fixture\Jwt;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The key pair of this program: ES256 on P-256 (FAPI 2.0 Security Profile §5.4.1), named by its thumbprint
 * (RFC 7638), its private half shown to nobody.
 */
final class SigningKeyTest extends TestCase
{
    #[Test]
    public function aDrawnKeyIsNamedByItsThumbprint(): void
    {
        // Given
        $key = SigningKey::generate();

        // When / Then
        static::assertSame($key->thumbprint(), $key->id());
    }

    #[Test]
    public function thePublicKeyCarriesNoPrivateMember(): void
    {
        // When
        $public = SigningKey::generate()->publicJwk();

        // Then
        static::assertArrayNotHasKey('d', $public);
    }

    #[Test]
    public function whatItSignsIsVerifiedByItsPublicKeyUnderEs256(): void
    {
        // Given
        $key = SigningKey::generate();

        // When
        $jwt = $key->sign(['alg' => 'none'], ['sub' => 'x']);

        // Then
        static::assertSame(['ES256', true], [Jwt::header($jwt)->nullableString('alg'), Jwt::verifies($jwt, $key->publicJwk())]);
    }

    #[Test]
    public function aKeyOfAnotherKindIsNotTheKeyOfAProfile(): void
    {
        // Given
        $rsa = new Document(JWKFactory::createRSAKey(2048)->all());

        // Then
        $this->expectException(UnreadableDocumentException::class);
        $this->expectExceptionMessageIs('The key of the profile must be an EC key on P-256.');

        // When
        SigningKey::fromDocument($rsa);
    }

    #[Test]
    public function aPublicKeyIsNotTheKeyOfAProfile(): void
    {
        // Given
        $public = new Document(SigningKey::generate()->publicJwk());

        // Then
        $this->expectException(UnreadableDocumentException::class);
        $this->expectExceptionMessageIs('The member "d" must be a string that is not empty.');

        // When
        SigningKey::fromDocument($public);
    }
}
