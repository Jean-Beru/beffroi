<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Method;

use function base64_encode;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\Certificate\DnsName;
use Heidi\Oidc\Domain\Client\Certificate\EmailAddressName;
use Heidi\Oidc\Domain\Client\Certificate\IpAddressName;
use Heidi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Heidi\Oidc\Domain\Client\Certificate\UriName;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\Certificates;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * "tls_client_auth" (RFC 8705 §2.1): the client presents a certificate of an authority the deployment
 * trusts, and the provider recognises it by the one value of §2.1.2 it registered.
 */
final class TlsClientAuthTest extends TestCase
{
    private const string ENDPOINT = 'https://id.acme.example/token';

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
        $this->client = Clients::withCertificateIdentity($this->tenant, new SubjectDistinguishedName('c=FR,o=Heidi Test,cn=heidi mtls client'));
        $this->clients->save($this->client);
    }

    /**
     * RFC 8705 §2.1.2: the certificate carries the subject distinguished name the client registered.
     */
    #[Test]
    public function itAuthenticatesAClientWhoseCertificateCarriesTheNameItRegistered(): void
    {
        // When
        $authenticated = $this->authenticate(Certificates::client());

        // Then
        static::assertSame($this->client, $authenticated->client);
    }

    /**
     * The chain is the edge's to judge (docs/mtls-at-the-edge.md), the name is the provider's: a
     * certificate of the very same authority that names somebody else authenticates nobody.
     */
    #[Test]
    public function anotherCertificateOfTheSameAuthorityIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: Client authentication failed.');

        // When
        $this->authenticate(Certificates::other());
    }

    #[Test]
    public function aRefusedCertificateIsRecordedAsSuch(): void
    {
        // When
        $this->failToAuthenticate(Certificates::other());

        // Then
        $event = $this->events->events[0] ?? static::fail('A refusal is recorded.');
        static::assertInstanceOf(ClientAuthenticationFailed::class, $event);
        static::assertSame(ClientAuthenticationFailureReason::UnexpectedCertificate, $event->reason);
    }

    /**
     * RFC 8705 §2.1.2: whichever of the five values the client registered, it is read out of the
     * certificate presented and compared to what the registration says.
     */
    #[Test]
    #[DataProvider('provideRegisteredNames')]
    public function itAuthenticatesOnTheKindOfNameTheClientRegistered(CertificateIdentityInterface $identity): void
    {
        // Given
        $client = Clients::withCertificateIdentity($this->tenant, $identity, 'named-client');
        $this->clients->save($client);

        // When
        $authenticated = $this->authenticate(Certificates::client(), 'named-client');

        // Then
        static::assertSame($client, $authenticated->client);
    }

    /**
     * RFC 8705 §3: the tokens of a request authenticated this way are bound to the certificate that
     * authenticated it.
     */
    #[Test]
    public function theTokensOfTheRequestAreBoundToTheCertificatePresented(): void
    {
        // Given
        $certificate = Certificates::client();

        // When
        $authenticated = $this->authenticate($certificate);

        // Then
        static::assertEquals(CertificateConfirmation::ofCertificate($certificate), $authenticated->confirmation);
    }

    /**
     * A request made without a certificate presents no mutual-TLS authentication at all: it names a
     * client and proves nothing, and naming oneself is not a method this client registered.
     */
    #[Test]
    public function aRequestWithoutACertificateProvesNothing(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);
        $this->expectExceptionMessageIs('invalid_client: Client authentication failed.');

        // When
        $this->authenticate(null);
    }

    /**
     * RFC 6749 §2.3.1: a client authenticates with the one method it registered, and a certificate is no
     * exception.
     */
    #[Test]
    public function aClientRegisteredForAnotherMethodIsRefused(): void
    {
        // Given
        $this->clients->save(Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            Methods::clientSecretBasic(),
            'basic-client',
        ));

        // When
        $this->failToAuthenticate(Certificates::client(), 'basic-client');

        // Then
        $event = $this->events->events[0] ?? static::fail('A refusal is recorded.');
        static::assertInstanceOf(ClientAuthenticationFailed::class, $event);
        static::assertSame(ClientAuthenticationFailureReason::UnexpectedMethod, $event->reason);
    }

    /**
     * What the edge hands over is read, never guessed at: bytes that are not a certificate authenticate
     * nobody and say so in the audit trail.
     */
    #[Test]
    public function bytesThatAreNotACertificateAuthenticateNobody(): void
    {
        // Given
        $certificate = ClientCertificate::fromBase64('bm90IGEgY2VydGlmaWNhdGU=') ?? static::fail('The fixture is base64.');

        // When
        $this->failToAuthenticate($certificate);

        // Then
        $event = $this->events->events[0] ?? static::fail('A refusal is recorded.');
        static::assertInstanceOf(ClientAuthenticationFailed::class, $event);
        static::assertSame(ClientAuthenticationFailureReason::UnreadableCertificate, $event->reason);
    }

    /**
     * A client reaching a host whose listener asks for a certificate presents one because it was asked,
     * not because it chose to authenticate with it: a certificate beside a credential of the request is
     * not a second mechanism of RFC 6749 §2.3, and the client authenticates with what it registered.
     */
    #[Test]
    public function aCertificateBesideAnotherCredentialIsNotASecondMechanism(): void
    {
        // Given
        $basic = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), Methods::clientSecretBasic(), 'basic-client');
        $this->clients->save($basic);

        // When
        $authenticated = $this->authenticator()->authenticate(
            $this->tenant,
            self::ENDPOINT,
            'Basic ' . base64_encode('basic-client:' . Clients::SECRET),
            [],
            $this->context,
            Certificates::client(),
        );

        // Then
        static::assertSame($basic, $authenticated->client);
    }

    /**
     * RFC 8705 §3 lets a provider bind the tokens of a client authenticated otherwise to the certificate
     * it presented; that is a registration of its own, which no client has here, so a client that
     * authenticated with its secret gets bearer tokens whatever its connection proved.
     */
    #[Test]
    public function theTokensOfAClientAuthenticatedOtherwiseAreNotBound(): void
    {
        // Given
        $this->clients->save(Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            Methods::clientSecretBasic(),
            'basic-client',
        ));

        // When
        $authenticated = $this->authenticator()->authenticate(
            $this->tenant,
            self::ENDPOINT,
            'Basic ' . base64_encode('basic-client:' . Clients::SECRET),
            [],
            $this->context,
            Certificates::client(),
        );

        // Then
        static::assertNull($authenticated->confirmation);
    }

    /**
     * RFC 8705 §2: the method is announced under the name a client registers.
     */
    #[Test]
    public function itAnnouncesItselfUnderTheNameOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('tls_client_auth', Methods::tlsClientAuth()->name());
    }

    /**
     * @return iterable<string, array{CertificateIdentityInterface}>
     */
    public static function provideRegisteredNames(): iterable
    {
        // the distinguished name a registration carries is written back by the reader of the provider,
        // as ClientDefinition does when it reads a client (RFC 8705 §2.1.2)
        yield 'the subject distinguished name' =>
            [new SubjectDistinguishedName(new PkiFrameworkCertificateReader()->distinguishedName(Certificates::SUBJECT_DN))];

        yield 'a dNSName' => [new DnsName(Certificates::DNS_NAME)];

        yield 'a uniformResourceIdentifier' => [new UriName(Certificates::URI)];

        yield 'an iPAddress' => [new IpAddressName(Certificates::IP_ADDRESS)];

        yield 'an rfc822Name' => [new EmailAddressName(Certificates::EMAIL_ADDRESS)];
    }

    private function authenticate(?ClientCertificate $certificate, string $clientId = 'mtls-client'): AuthenticatedClient
    {
        return $this->authenticator()->authenticate(
            $this->tenant,
            self::ENDPOINT,
            null,
            [
                'client_id' => $clientId,
            ],
            $this->context,
            $certificate,
        );
    }

    private function failToAuthenticate(?ClientCertificate $certificate, string $clientId = 'mtls-client'): OAuth2Exception
    {
        try {
            $this->authenticate($certificate, $clientId);
        } catch (OAuth2Exception $exception) {
            return $exception;
        }

        static::fail('The authentication should have failed.');
    }

    private function authenticator(?ClockInterface $clock = null): ClientAuthenticator
    {
        return new ClientAuthenticator($this->clients, Methods::all(), $clock ?? new MockClock('2026-09-22T12:00:00+00:00'), $this->events);
    }
}
