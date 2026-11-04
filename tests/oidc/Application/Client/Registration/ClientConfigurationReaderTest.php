<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationAccess;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationReader;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7592 §2.1
 */
final class ClientConfigurationReaderTest extends TestCase
{
    private const string TOKEN = 'a-value-the-provider-handed-that-client';

    private const string CLIENT_ID = 'drawn-identifier';

    #[Test]
    public function aClientSeesWhatItRegisteredAndWhereItReadsItself(): void
    {
        // When
        $response = $this->read('Bearer ' . self::TOKEN);

        // Then
        static::assertSame(ClientInformationResponse::INFORMED, $response->statusCode);
        static::assertSame(
            [
                'client_id' => self::CLIENT_ID,
                'client_id_issued_at' => Fixtures::now()->getTimestamp(),
                'registration_client_uri' => 'https://id.acme.example/register/drawn-identifier',
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            $response->parameters(),
        );
    }

    #[Test]
    public function aClientIsNeverAnsweredItsSecretAgain(): void
    {
        // When
        $response = $this->read('Bearer ' . self::TOKEN);

        // Then
        static::assertArrayNotHasKey('client_secret', $response->parameters());
    }

    /**
     * RFC 7592 §2.3
     */
    #[Test]
    public function aReadHandsOutNoNewToken(): void
    {
        // When
        $response = $this->read('Bearer ' . self::TOKEN);

        // Then
        static::assertNull($response->registrationAccessToken);
    }

    #[Test]
    public function aRequestThatReadsNoClientReadsNothing(): void
    {
        // Then
        $this->expectException(UnauthorizedClientConfigurationException::class);

        // When
        $this->read(null);
    }

    private function read(?string $header): ClientInformationResponse
    {
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientStore();
        $clients->save(new ClientRecord(
            Uuid::v7(),
            $tenant,
            self::CLIENT_ID,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            new HashedClientSecret(new PasswordHash(new Argon2id(), 'the-hash-of-what-was-answered-once')),
            DrawnSecret::digestOf(self::TOKEN),
            Fixtures::now(),
        ));

        return new ClientConfigurationReader(new ClientConfigurationAccess($clients), new Endpoints())->read($tenant, self::CLIENT_ID, $header);
    }
}
