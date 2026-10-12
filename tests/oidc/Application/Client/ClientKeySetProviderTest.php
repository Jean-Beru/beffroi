<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The client's half of a published key set (RFC 7591 §2): the set its registration names, read by the
 * one class that reads a published set (PublishedKeySetProviderTest), and what being unable to read it
 * means for the method that was authenticating the client.
 */
final class ClientKeySetProviderTest extends TestCase
{
    private const string JWKS_URI = 'https://key.example/jwks';

    private Tenant $tenant;

    private FakeClientJwksFetcher $fetcher;

    private ClientKeySetProvider $provider;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->fetcher = new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]);
        $this->provider = new ClientKeySetProvider(new PublishedKeySetProvider(
            $this->fetcher,
            new InMemoryClientJwksCache(),
            new MockClock('2026-09-15T10:00:00+00:00'),
            new DateInterval('PT300S'),
        ));
    }

    /**
     * RFC 7591 §2: a client that wrote its keys down is answered them, and nothing is called.
     */
    #[Test]
    public function theSetAClientWroteDownIsItsAnswer(): void
    {
        // Given
        $client = Clients::withKeys($this->tenant);

        // When
        $keys = $this->provider->keysOf($client, ClientAssertions::KEY_ID);

        // Then
        static::assertSame($client->registration->jwks, $keys);
        static::assertSame([], $this->fetcher->fetched);
    }

    /**
     * RFC 7591 §2: a client that registered a "jwks_uri" has it read, and no other URL.
     */
    #[Test]
    public function theSetOfAClientIsReadFromTheUrlItRegistered(): void
    {
        // When
        $keys = $this->provider->keysOf($this->remoteClient(), ClientAssertions::KEY_ID);

        // Then
        static::assertSame(ClientAssertions::publishedKeys()->keys, $keys->keys);
        static::assertSame([self::JWKS_URI], array_map(static fn (ClientUri $uri): string => $uri->value, $this->fetcher->fetched));
    }

    /**
     * A client that publishes neither a set nor a URL publishes nothing to verify a signature against,
     * and nothing is called to find out.
     */
    #[Test]
    public function aClientThatPublishesNoKeyIsRefused(): void
    {
        // Given
        $client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIs('The client "oidc-demo" publishes no key.');

        // When
        $this->provider->keysOf($client, null);
    }

    /**
     * RFC 6749 §5.2: keys that cannot be read are a refusal of the method that was authenticating the
     * client and not an error of the endpoint.
     */
    #[Test]
    public function keysThatCannotBeReadRefuseTheMethodThatWasAuthenticating(): void
    {
        // Given
        $this->fetcher->failure = new ClientKeysUnavailableException('https://key.example/jwks answered 500.');
        $method = Methods::privateKeyJwt();

        // When
        try {
            $this->provider->keysAuthenticating($this->remoteClient(), ClientAssertions::KEY_ID, $method);
            static::fail('Keys that cannot be read should refuse the method.');
        } catch (ClientAuthenticationFailure $failure) {
            // Then
            static::assertSame(ClientAuthenticationFailureReason::UnreadableClientKeys, $failure->reason);
            static::assertSame('https://key.example/jwks answered 500.', $failure->getPrevious()?->getMessage());
        }
    }

    private function remoteClient(): Client
    {
        return Clients::withKeys($this->tenant, 'remote-client', jwksUri: new ClientUri(self::JWKS_URI));
    }
}
