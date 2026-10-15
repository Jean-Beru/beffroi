<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use function base64_encode;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Bridge\Model\DeclaredServiceProviderReader;
use Beffroi\Saml\Bridge\Model\ModelLogoutRequestReceiver;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\InMemoryAcceptedMetadata;
use Beffroi\Saml\Tests\Fixture\InMemoryLogoutReplayStore;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOutRequests;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use function explode;
use function parse_url;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.5 step 1, S-22, S-23, S-27: a logout request of a declared service provider received over
 * either binding, validated by the model at the URL of the single logout service of the tenant, remembered once, and
 * the single logout service its answer goes to resolved among those of the accepted metadata; anything else refused
 * without a SAML answer.
 */
final class ModelLogoutRequestReceiverTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private const string SINGLE_LOGOUT = self::ISSUER . FixedEndpoints::SINGLE_LOGOUT;

    private const string UNREGISTERED = 'https://unregistered.example.org/saml';

    private const string POST_LOCATION = ServiceProviderDocuments::SIGNED . '/slo/post';

    private const string POST_RESPONSE_LOCATION = ServiceProviderDocuments::SIGNED . '/slo/post/response';

    private Tenant $tenant;

    private InMemoryAcceptedMetadata $accepted;

    private InMemoryLogoutReplayStore $replay;

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->accepted = new InMemoryAcceptedMetadata();
        $this->replay = new InMemoryLogoutReplayStore();
        $this->clock = new MockClock(Fixtures::now());
        $this->accept([
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT),
            new Endpoint(Binding::HttpPost, self::POST_LOCATION, self::POST_RESPONSE_LOCATION),
        ]);
    }

    /**
     * S-22, B-2, S-27: a request signed over its query string is accepted, its NameID, its session indexes and its
     * RelayState as they were sent, its answer going to the single logout service of the metadata on HTTP-Redirect.
     */
    #[Test]
    public function aRequestSignedOverHttpRedirectIsAccepted(): void
    {
        // When
        $request = $this->receiver()->redirect($this->tenant, $this->redirected());

        // Then
        static::assertEquals(
            SignOutRequests::request(
                'alice-at-sp',
                ['the-session'],
                PersistentNameId::FORMAT,
                self::ISSUER . FixedEndpoints::METADATA,
                ServiceProviderDocuments::SIGNED,
            ),
            $request,
        );
    }

    /**
     * S-22, M-2, S-27, SAML Metadata §2.2.2: a request signed in its XML over HTTP-POST is accepted, its answer going to
     * the ResponseLocation of the single logout service on HTTP-POST.
     */
    #[Test]
    public function aRequestSignedOverHttpPostIsAnsweredAtTheResponseLocation(): void
    {
        // When
        $request = $this->receiver()->post($this->tenant, $this->posted());

        // Then
        static::assertSame(
            [SignOutRequests::POST, self::POST_RESPONSE_LOCATION, 'state-1'],
            [$request->answerBinding, $request->answerLocation, $request->relayState],
        );
    }

    /**
     * S-27: without a single logout service on the binding of the request, the answer goes to the first one listed.
     */
    #[Test]
    public function withoutAServiceOnTheBindingOfTheRequestTheFirstListedAnswers(): void
    {
        // Given
        $this->accept([new Endpoint(Binding::HttpPost, self::POST_LOCATION)]);

        // When
        $request = $this->receiver()->redirect($this->tenant, $this->redirected());

        // Then
        static::assertSame([SignOutRequests::POST, self::POST_LOCATION], [$request->answerBinding, $request->answerLocation]);
    }

    /**
     * S-27: the first single logout service listed on the binding of the request answers, not a later one.
     */
    #[Test]
    public function theFirstServiceOnTheBindingOfTheRequestAnswers(): void
    {
        // Given
        $this->accept([
            new Endpoint(Binding::HttpPost, self::POST_LOCATION),
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT),
            new Endpoint(Binding::HttpRedirect, SignOutRequests::SINGLE_LOGOUT . '/other'),
        ]);

        // When
        $request = $this->receiver()->redirect($this->tenant, $this->redirected());

        // Then
        static::assertSame([SignOutRequests::REDIRECT, SignOutRequests::SINGLE_LOGOUT], [$request->answerBinding, $request->answerLocation]);
    }

    /**
     * S-22, S-27: a service provider whose metadata list no single logout service is refused: its answer could go
     * nowhere.
     */
    #[Test]
    public function aServiceProviderWithoutSingleLogoutServiceIsRefused(): void
    {
        // Given
        $this->accept([]);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The metadata of the service provider list no single logout service the answer could go to (spec/saml.md S-27).');

        // When
        $this->receiver()->redirect($this->tenant, $this->redirected());
    }

    /**
     * S-23, M-11, issue #708: the same request received twice is refused the second time.
     */
    #[Test]
    public function theSameRequestIsRefusedTheSecondTime(): void
    {
        // Given
        $query = $this->redirected();
        $this->receiver()->redirect($this->tenant, $query);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The logout message was already accepted from its issuer (M-11).');

        // When
        $this->receiver()->redirect($this->tenant, $query);
    }

    /**
     * S-23, M-11: the store of the tenant remembers the issuer and the ID of the request until its IssueInstant plus
     * maxMessageAge and the skew.
     */
    #[Test]
    public function theRequestIsRememberedUnderTheTenant(): void
    {
        // When
        $this->receiver()->redirect($this->tenant, $this->redirected());

        // Then
        static::assertEquals(
            Fixtures::now()->modify('+480 seconds'),
            $this->replay->expiresAt($this->tenant, ServiceProviderDocuments::SIGNED, SignOutRequests::ID),
        );
    }

    /**
     * S-22, M-2, SAML Profiles §4.4.4.1: a request whose query string carries no signature, and none in its XML.
     */
    #[Test]
    public function anUnsignedRequestOverHttpRedirectIsRefused(): void
    {
        // Given
        [$query] = explode('&SigAlg=', $this->redirected());

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->receiver()->redirect($this->tenant, $query);
    }

    /**
     * S-22, M-2: a request posted without its XML signature, from a provider that signs nothing else either.
     */
    #[Test]
    public function anUnsignedRequestOverHttpPostIsRefused(): void
    {
        // Given
        $document = new Serializer()->serialize(new LogoutRequestWriter()->write(self::request(), null));

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->receiver()->post($this->tenant, ['SAMLRequest' => base64_encode($document)]);
    }

    /**
     * S-22, section 6.3 step 1: an issuer nobody declared.
     */
    #[Test]
    public function anIssuerNobodyDeclaredIsRefused(): void
    {
        // Given
        $request = self::request(self::UNREGISTERED . '/nobody');

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The Issuer of the request is no service provider this tenant declares (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, new PostSender()->logoutRequest($request, self::signing(), 'state-1')->fields);
    }

    /**
     * S-22, section 6.3 step 1: a service provider declared whose metadata were never accepted.
     */
    #[Test]
    public function aServiceProviderWithoutAcceptedMetadataIsRefused(): void
    {
        // Given
        $request = self::request(self::UNREGISTERED);

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request has no metadata accepted yet (spec/saml.md section 6.3 step 1).');

        // When
        $this->receiver()->post($this->tenant, new PostSender()->logoutRequest($request, self::signing(), 'state-1')->fields);
    }

    /**
     * S-22, issue #735: a LogoutResponse answers a request the identity provider has not sent.
     */
    #[Test]
    public function aLogoutResponseIsRefused(): void
    {
        // Given
        $response = new LogoutResponse(
            '_1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e',
            Fixtures::now(),
            new Issuer(ServiceProviderDocuments::SIGNED),
            self::SINGLE_LOGOUT,
            SignOutRequests::ID,
            new Status(StatusCode::Success),
        );

        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIs('A LogoutResponse answers a request this identity provider has not sent: it sends none before issue #735 (spec/saml.md S-22).');

        // When
        $this->receiver()->redirect(
            $this->tenant,
            (string) parse_url(new RedirectSender()->logoutResponse($response, self::signing()), PHP_URL_QUERY),
        );
    }

    /**
     * B-1: what the binding refuses of a query string is refused before anything else.
     */
    #[Test]
    public function aQueryStringTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->redirect($this->tenant, 'RelayState=state-1');
    }

    /**
     * B-1: what the binding refuses of a form is refused before anything else.
     */
    #[Test]
    public function aFormTheBindingRefusesIsRefused(): void
    {
        // Then
        $this->expectException(LogoutRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(B-1)');

        // When
        $this->receiver()->post($this->tenant, ['RelayState' => 'state-1']);
    }

    /**
     * The metadata of the signed service provider accepted for the tenant, listing the single logout services given.
     *
     * @param list<Endpoint> $singleLogoutServices
     */
    private function accept(array $singleLogoutServices): void
    {
        $this->accepted->save(new AcceptedMetadata(
            Uuid::v7(),
            $this->tenant,
            ServiceProviderDocuments::SIGNED,
            ServiceProviderDocuments::signed(null, 'sp', $singleLogoutServices),
            null,
            Fixtures::now(),
        ));
    }

    private function redirected(): string
    {
        return (string) parse_url(new RedirectSender()->logoutRequest(self::request(), self::signing(), 'state-1'), PHP_URL_QUERY);
    }

    /**
     * @return array<string, string>
     */
    private function posted(): array
    {
        return new PostSender()->logoutRequest(self::request(), self::signing(), 'state-1')->fields;
    }

    private function receiver(): ModelLogoutRequestReceiver
    {
        return new ModelLogoutRequestReceiver(
            new DeclaredServiceProviderReader(
                new ConfigurationServiceProviders(
                    'acme',
                    [
                        ServiceProviderDocuments::SIGNED => [
                            'metadata' => '/etc/saml/sp.xml',
                        ],
                        self::UNREGISTERED => [
                            'metadata' => '/etc/saml/unregistered.xml',
                        ],
                    ],
                    new FixedClaims(),
                ),
                $this->accepted,
                new ModelServiceProviderMetadataReader($this->clock),
            ),
            new FixedEndpoints(),
            $this->replay,
            $this->clock,
        );
    }

    private static function request(string $issuer = ServiceProviderDocuments::SIGNED): LogoutRequest
    {
        return new LogoutRequest(
            SignOutRequests::ID,
            Fixtures::now(),
            new Issuer($issuer),
            self::SINGLE_LOGOUT,
            null,
            new NameId('alice-at-sp', NameIdFormat::Persistent, self::ISSUER . FixedEndpoints::METADATA, ServiceProviderDocuments::SIGNED),
            ['the-session'],
        );
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
