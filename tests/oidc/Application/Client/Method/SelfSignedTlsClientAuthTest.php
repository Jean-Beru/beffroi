<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Method;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\Confirmation;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClientJwksFetcher;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * "self_signed_tls_client_auth" (RFC 8705 §2.2): the client presents a certificate it signed itself, and
 * the provider authenticates it when that certificate is one of those the client publishes.
 */
final class SelfSignedTlsClientAuthTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

    private const string JWKS_URI = 'https://self-signed.example/jwks';

    private Tenant $tenant;

    private RequestContext $context;

    private InMemoryClientRepository $clients;

    private RecordingEventDispatcher $events;

    private Client $client;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->clients = new InMemoryClientRepository();
        $this->events = new RecordingEventDispatcher();
        $this->client = Clients::withPublishedCertificate($this->tenant);
        $this->clients->save($this->client);
    }

    /**
     * RFC 8705 §2.2: the certificate presented is the one the client publishes in the "x5c" of a key of
     * its JWK Set (RFC 7517 §4.7). No chain is built and no authority is asked: what is trusted is what
     * the client published.
     */
    #[Test]
    public function itAuthenticatesACertificateTheClientPublishes(): void
    {
        // When
        $authenticated = $this->authenticate(Certificates::selfSigned());

        // Then
        static::assertSame($this->client, $authenticated->client);
    }

    /**
     * RFC 7517 §4.9: a key may name its certificate by thumbprint instead of carrying it, which is the
     * same certificate said in fewer bytes.
     */
    #[Test]
    public function itAuthenticatesACertificateTheClientNamesByItsThumbprint(): void
    {
        // Given
        $client = Clients::withPublishedCertificate($this->tenant, Certificates::thumbprintedIn(Certificates::selfSigned()), 'thumbprint-client');
        $this->clients->save($client);

        // When
        $authenticated = $this->authenticate(Certificates::selfSigned(), 'thumbprint-client');

        // Then
        static::assertSame($client, $authenticated->client);
    }

    /**
     * The certificate is what is compared, not the key inside it: the same names signed again are
     * another certificate, and one the client never published. A client that rotates its certificate
     * publishes the new one first, as it does for a signing key.
     */
    #[Test]
    public function theSameCertificateReissuedIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: Client authentication failed.');

        // When
        $this->authenticate(Certificates::reissued());
    }

    #[Test]
    public function aCertificateTheClientDoesNotPublishIsRecordedAsSuch(): void
    {
        // When
        $this->failToAuthenticate(Certificates::client());

        // Then
        $event = $this->events->events[0] ?? static::fail('A refusal is recorded.');
        static::assertInstanceOf(ClientAuthenticationFailed::class, $event);
        static::assertSame(ClientAuthenticationFailureReason::UnexpectedCertificate, $event->reason);
    }

    /**
     * RFC 8705 §3: the tokens of a request authenticated this way are bound to the certificate that
     * authenticated it, self-signed or not.
     */
    #[Test]
    public function theTokensOfTheRequestAreBoundToTheCertificatePresented(): void
    {
        // Given
        $certificate = Certificates::selfSigned();

        // When
        $authenticated = $this->authenticate($certificate);

        // Then
        static::assertEquals(Confirmation::ofCertificate($certificate), $authenticated->confirmation);
    }

    /**
     * RFC 7591 §2: a client may publish its keys behind a "jwks_uri"; a client whose keys cannot be read
     * back authenticates nobody, and the audit trail says why.
     */
    #[Test]
    public function aClientWhoseKeysCannotBeReadBackIsRefused(): void
    {
        // Given
        $this->clients->save(new Client($this->tenant, 'remote-client', 'Client publishing its certificate behind a URI', Methods::selfSignedTlsClientAuth(), null, $this->client->redirectUris, jwksUri: new ClientUri(self::JWKS_URI)));
        $fetcher = new FakeClientJwksFetcher([]);
        $fetcher->failure = new ClientKeysUnavailableException('The keys of the client could not be read back.');

        // When
        $this->failToAuthenticate(Certificates::selfSigned(), 'remote-client', $fetcher);

        // Then
        $event = $this->events->events[0] ?? static::fail('A refusal is recorded.');
        static::assertInstanceOf(ClientAuthenticationFailed::class, $event);
        static::assertSame(ClientAuthenticationFailureReason::UnreadableClientKeys, $event->reason);
    }

    /**
     * RFC 8705 §2.2: the method is announced under the name a client registers.
     */
    #[Test]
    public function itAnnouncesItselfUnderTheNameOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('self_signed_tls_client_auth', Methods::selfSignedTlsClientAuth()->name());
    }

    private function authenticate(ClientCertificate $certificate, string $clientId = 'self-signed-client', ?FakeClientJwksFetcher $fetcher = null): AuthenticatedClient
    {
        return $this->authenticator($fetcher)
            ->authenticate($this->tenant, self::ENDPOINT, null, [
                'client_id' => $clientId,
            ], $this->context, $certificate);
    }

    private function failToAuthenticate(ClientCertificate $certificate, string $clientId = 'self-signed-client', ?FakeClientJwksFetcher $fetcher = null): OAuth2Exception
    {
        try {
            $this->authenticate($certificate, $clientId, $fetcher);
        } catch (OAuth2Exception $exception) {
            return $exception;
        }

        static::fail('The authentication should have failed.');
    }

    private function authenticator(?FakeClientJwksFetcher $fetcher = null): ClientAuthenticator
    {
        $clock = new MockClock('2026-09-22T12:00:00+00:00');

        return new ClientAuthenticator($this->clients, Methods::all(keys: Methods::keySetProvider($fetcher, $clock)), $clock, $this->events);
    }
}
