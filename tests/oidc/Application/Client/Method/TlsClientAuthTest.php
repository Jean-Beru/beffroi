<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Method;

use function base64_encode;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Certificate\DnsName;
use Beffroi\Oidc\Domain\Client\Certificate\EmailAddressName;
use Beffroi\Oidc\Domain\Client\Certificate\IpAddressName;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Certificate\UriName;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 8705 §2.1, §2.1.2
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
        $this->client = Clients::withCertificateIdentity($this->tenant, new SubjectDistinguishedName('c=FR,o=Beffroi Test,cn=beffroi mtls client'));
        $this->clients->save($this->client);
    }

    /**
     * RFC 8705 §2.1.2
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
     * Architecture §6
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
     * RFC 8705 §2.1.2
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
     * RFC 8705 §3
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
     * RFC 6749 §2.3.1
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
     * RFC 6749 §2.3
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
     * RFC 8705 §3
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
     * RFC 8705 §2
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
        // The registered name is written back by the provider's reader, as ClientDefinition does (RFC 8705 §2.1.2).
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
        return new ClientAuthenticator(
            $this->clients,
            Methods::all(),
            Methods::requestParser(),
            $clock ?? new MockClock('2026-09-22T12:00:00+00:00'),
            $this->events,
            new FakeClientLoadBudget(),
        );
    }
}
