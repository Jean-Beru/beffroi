<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\ClientConfigurationAccess;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7592 §2.3
 */
final class ClientConfigurationAccessTest extends TestCase
{
    private const string TOKEN = 'a-value-the-provider-handed-that-client';

    private const string CLIENT_ID = 'drawn-identifier';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
    }

    #[Test]
    public function aClientPresentingItsOwnTokenIsTheClientTheUriAnswersFor(): void
    {
        // Given
        $record = $this->register();

        // When
        $granted = $this->granted(self::CLIENT_ID, 'Bearer ' . self::TOKEN);

        // Then
        static::assertSame($record, $granted);
    }

    /**
     * RFC 9110 §11.6.1
     */
    #[Test]
    public function theSchemeIsReadWithoutRegardToCase(): void
    {
        // Given
        $this->register();

        // When
        $granted = $this->granted(self::CLIENT_ID, 'bearer ' . self::TOKEN);

        // Then
        static::assertSame(self::CLIENT_ID, $granted->clientId);
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideRefusedRequests')]
    public function aRequestThatReadsNoClientIsRefusedTheSameWay(string $clientId, ?string $header): void
    {
        // Given
        $this->register();
        $this->register('another-drawn-identifier', 'a-value-the-provider-handed-another-client');

        // Then
        $this->expectException(UnauthorizedClientConfigurationException::class);
        $this->expectExceptionMessageIs('invalid_token: The request does not carry the registration access token of this client (RFC 7592 section 2.3).');

        // When
        $this->granted($clientId, $header);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideRefusedRequests(): iterable
    {
        yield 'no Authorization header at all' => [self::CLIENT_ID, null];

        yield 'a header of another scheme' => [self::CLIENT_ID, 'Basic ' . self::TOKEN];

        yield 'a value nobody was handed' => [self::CLIENT_ID, 'Bearer a-value-nobody-was-handed'];

        yield 'the token of another client at this client URI' => [self::CLIENT_ID, 'Bearer a-value-the-provider-handed-another-client'];

        yield 'the token of this client at another client URI' => ['another-drawn-identifier', 'Bearer ' . self::TOKEN];

        yield 'a client this store holds none of' => ['a-client-nobody-registered', 'Bearer ' . self::TOKEN];
    }

    #[Test]
    public function aClientOfAnotherTenantIsReadByNothingHere(): void
    {
        // Given
        $this->register(tenant: Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        $this->expectException(UnauthorizedClientConfigurationException::class);

        // When
        $this->granted(self::CLIENT_ID, 'Bearer ' . self::TOKEN);
    }

    private function register(string $clientId = self::CLIENT_ID, string $token = self::TOKEN, ?Tenant $tenant = null): ClientRecord
    {
        $record = new ClientRecord(
            Uuid::v7(),
            $tenant ?? $this->tenant,
            $clientId,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
            DrawnSecret::digestOf($token),
            Fixtures::now(),
        );
        $this->clients->save($record);

        return $record;
    }

    private function granted(string $clientId, ?string $header): ClientRecord
    {
        return new ClientConfigurationAccess($this->clients)->granted($this->tenant, $clientId, $header);
    }
}
