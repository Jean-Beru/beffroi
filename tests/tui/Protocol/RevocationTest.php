<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\DpopProofs;
use Beffroi\Tui\Protocol\PrivateKeyJwt;
use Beffroi\Tui\Protocol\ProviderEndpoint;
use Beffroi\Tui\Protocol\Revocation;
use Beffroi\Tui\Protocol\TokenResponse;
use Beffroi\Tui\Provider\ProviderMetadata;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7009: a provider that announces no revocation endpoint takes nothing back, and says so through this program.
 */
final class RevocationTest extends TestCase
{
    #[Test]
    public function aProviderWithoutARevocationEndpointIsSaidToTakeNothingBack(): void
    {
        // Given
        $http = RecordedRequests::answering([]);
        $clock = new MockClock();
        $provider = new ProviderMetadata(
            FakeProvider::ISSUER,
            FakeProvider::ISSUER . '/authorize',
            FakeProvider::ISSUER . '/par',
            FakeProvider::ISSUER . '/token',
            FakeProvider::ISSUER . '/jwks',
            ['ES256'],
        );
        $revocation = new Revocation(
            new ProviderEndpoint(
                $http->client,
                new PrivateKeyJwt(FakeProvider::CLIENT_ID, SigningKey::generate(), FakeProvider::ISSUER, $clock),
                new DpopProofs(SigningKey::generate(), $clock),
            ),
            $provider,
        );

        // When
        $notes = $revocation->handBack(TokenResponse::fromDocument(new Document(['access_token' => 'at', 'token_type' => 'DPoP'])));

        // Then
        static::assertSame(
            [['The provider announces no revocation endpoint (RFC 7009 §2): the tokens of this session stay valid until they expire.'], []],
            [$notes, $http->requests],
        );
    }
}
