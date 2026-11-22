<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\PrivateKeyJwt;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Jwt;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * OIDC Core §9 and RFC 7523 §2.2: the client authenticates with an assertion its key signs.
 */
final class PrivateKeyJwtTest extends TestCase
{
    /**
     * RFC 7523 §3, FAPI 2.0 Security Profile §5.3.3.1 item 5: the client is the issuer and the subject, the
     * issuer identifier of the provider the audience as a string, and the assertion is worth a minute.
     */
    #[Test]
    public function theAssertionNamesTheClientAndTheProviderAlone(): void
    {
        // Given
        $authentication = new PrivateKeyJwt(
            FakeProvider::CLIENT_ID,
            SigningKey::generate(),
            FakeProvider::ISSUER,
            new MockClock(new DateTimeImmutable('@' . FakeProvider::NOW)),
        );

        // When
        $claims = Jwt::claims($authentication->parameters()['client_assertion'] ?? '')->members;

        // Then
        static::assertSame(
            [FakeProvider::CLIENT_ID, FakeProvider::CLIENT_ID, FakeProvider::ISSUER, FakeProvider::NOW, FakeProvider::NOW + 60],
            [$claims['iss'] ?? null, $claims['sub'] ?? null, $claims['aud'] ?? null, $claims['iat'] ?? null, $claims['exp'] ?? null],
        );
    }

    #[Test]
    public function theAssertionIsSignedByTheKeyOfTheClientAndNamesIt(): void
    {
        // Given
        $key = SigningKey::generate();
        $authentication = new PrivateKeyJwt(FakeProvider::CLIENT_ID, $key, FakeProvider::ISSUER, new MockClock());

        // When
        $assertion = $authentication->parameters()['client_assertion'] ?? '';

        // Then
        static::assertSame([true, $key->thumbprint()], [Jwt::verifies($assertion, $key->publicJwk()), Jwt::header($assertion)->nullableString('kid')]);
    }

    #[Test]
    public function anAssertionIsDrawnForOneRequest(): void
    {
        // Given
        $authentication = new PrivateKeyJwt(FakeProvider::CLIENT_ID, SigningKey::generate(), FakeProvider::ISSUER, new MockClock());

        // When
        $first = Jwt::claims($authentication->parameters()['client_assertion'] ?? '')->nullableString('jti');
        $second = Jwt::claims($authentication->parameters()['client_assertion'] ?? '')->nullableString('jti');

        // Then
        static::assertNotSame($first, $second);
    }

    #[Test]
    public function theParametersAreThoseOfAJwtBearerAssertion(): void
    {
        // When
        $parameters = new PrivateKeyJwt(FakeProvider::CLIENT_ID, SigningKey::generate(), FakeProvider::ISSUER, new MockClock())->parameters();

        // Then
        static::assertSame(
            [FakeProvider::CLIENT_ID, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
            [$parameters['client_id'] ?? null, $parameters['client_assertion_type'] ?? null],
        );
    }
}
