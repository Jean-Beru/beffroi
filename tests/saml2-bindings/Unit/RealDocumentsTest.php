<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Bindings\Tests\Unit\Internal\CodecFixtures;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_pad;

/**
 * Section 9.4
 */
final class RealDocumentsTest extends TestCase
{
    use CodecFixtures;

    private const string SP = 'http://localhost:8092/simplesaml/module.php/saml/sp/';

    private const string IDP = 'http://localhost:8091/simplesaml/module.php/saml/idp/';

    private const string MODEL = 'http://localhost:8083/model/';

    private const string BINDINGS = 'http://localhost:8093/bindings/';

    private const string SEPTEMBER_30 = '2026-09-30T13:07:34Z';

    private const string OCTOBER_1_LOGIN = '2026-10-01T11:03:33Z';

    private const string OCTOBER_1 = '2026-10-01T11:03:34Z';

    private const string OCTOBER_1_LONG_RETURN_TO = '2026-10-01T11:03:37Z';

    private const string KEYCLOAK = 'http://localhost:8190/realms/';

    private const string KEYCLOAK_BINDINGS_IDP = 'https://idp.saml2-bindings.test/';

    private const string KEYCLOAK_BINDINGS_SP = 'https://sp.saml2-bindings.test/';

    private const string KEYCLOAK_OCTOBER_1 = '2026-10-01T11:37:37Z';

    /**
     * Section 9.4, section 6.1, section 8, B-2, B-5, B-9, SAML Bindings §3.4.4.1, §3.4.3, findings F-5 and K-4
     */
    #[Test]
    #[DataProvider('provideAuthnRequests')]
    public function itVerifiesAndValidatesTheSignedAuthnRequestsOfRealServiceProviders(
        string $query,
        string $capturedAt,
        string $serviceProvider,
        IdentityProvider $self,
        string $receivedAt,
        string $id,
        string $assertionConsumerService,
        string $relayState,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(self::fixture($query));

        // When
        $accepted = $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock($capturedAt)),
            self::serviceProvider($serviceProvider, $capturedAt),
            $self,
            $receivedAt,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, $assertionConsumerService, $relayState],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->assertionConsumerService->location,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, string, IdentityProvider, string, string, string, string}>
     */
    public static function provideAuthnRequests(): iterable
    {
        yield 'for-model to saml2-model, 30 September 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt',
            self::SEPTEMBER_30,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml',
            self::modelIdentityProvider(),
            self::MODEL . 'idp/sso',
            '_ef4cb04a9098a02745f19851d7b70d2e7712c1aa4d',
            'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/for-model',
            'http://localhost:8082/simplesaml/session.php',
        ];
        yield 'default-sp to its own identity provider, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-query-2026-10-01.txt',
            self::OCTOBER_1_LOGIN,
            'real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml',
            self::simpleSamlPhpIdentityProvider(),
            self::IDP . 'singleSignOnService',
            '_b49530d286d4adf9a5a5ca3eecbb1b5611a1f15c38',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            'http://localhost:8092/simplesaml/module.php/core/welcome',
        ];
        yield 'for-bindings to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/sso',
            '_dcfb5cad9e75a4f54f05896bc454dbca210b085829',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/for-bindings',
            'http://localhost:8092/simplesaml/session.php',
        ];
        yield 'Keycloak\'s broker to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-authnrequest-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
            'ID_3894a772-c6e9-416a-ad76-846f38c871e7',
            self::KEYCLOAK . 'sp/broker/bindings/endpoint',
            '-EyR6_MhiYlEDqynO29Wij-_WW7CjnpUloGSVEFjVnI.kyrCguQFzP4.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'for-bindings to this package, a ReturnTo of 105 bytes, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt',
            self::OCTOBER_1_LONG_RETURN_TO,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/sso',
            '_118cf0716e0bd05824bf5b174d045953333cd2504c',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/for-bindings',
            'http://localhost:8092/simplesaml/session.php?return-to-return-to-return-to-return-to-return-to-return-to-',
        ];
        yield 'Keycloak\'s broker to this package, a client whose internal ID is not a UUID, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
            'ID_f023bf10-c1f3-4217-a0ab-6febc02aac85',
            self::KEYCLOAK . 'sp/broker/bindings/endpoint',
            'FxVRi7Piwr1RNqcv7MoiqBwdwZk9AjwuFDkd8HQ5BMg.6aPnW3NLLrQ.YS1jbGllbnQtb2YtcmVhbG0tc3Atd2hvc2UtaW50ZXJuYWwtaWQtaXMtbm8tdXVpZA',
        ];
    }

    /**
     * Section 9.4, B-5, SAML Profiles §4.1.2, model.md section 8, finding K-2
     */
    #[Test]
    public function itRefusesTheAuthnRequestOfKeycloaksBrokerAskingForItsResponseOverHttpRedirect(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(
            self::fixture('real/keycloak-26.7.4-sp-authnrequest-to-bindings-redirect-binding-refused-query-2026-10-01.txt'),
        );

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1)),
            self::serviceProvider(
                'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
                self::KEYCLOAK_OCTOBER_1,
            ),
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
        );
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, M-3, saml2-model's finding 2
     */
    #[Test]
    public function itRefusesTheUnsignedAuthnRequestOfKeycloaksBrokerUnderItsDefaults(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(
            self::fixture('real/keycloak-26.7.4-sp-authnrequest-unsigned-refused-query-2026-10-01.txt'),
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1)),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::keycloakIdentityProvider(),
            self::KEYCLOAK . 'idp/protocol/saml',
        );
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.1
     */
    #[Test]
    public function itRefusesTheUnsignedLogoutRequestOfKeycloaksBrokerUnderItsDefaults(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(
            self::fixture('real/keycloak-26.7.4-sp-logoutrequest-unsigned-refused-query-2026-10-01.txt'),
        );
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1), new InMemoryReplayGuard()),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::keycloakIdentityProvider(),
            self::KEYCLOAK . 'idp/protocol/saml',
        );
    }

    /**
     * Section 9.4, section 6.1, B-2, B-5, SAML Profiles §4.4.4.1
     *
     * @param list<string> $sessionIndexes
     */
    #[Test]
    #[DataProvider('provideLogoutRequests')]
    public function itVerifiesAndValidatesTheSignedLogoutRequestsOfRealServiceProviders(
        string $query,
        string $capturedAt,
        string $serviceProvider,
        IdentityProvider $self,
        string $receivedAt,
        string $id,
        NameIdFormat $format,
        string $nameId,
        array $sessionIndexes,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        // When
        $accepted = $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), self::clock($capturedAt), new InMemoryReplayGuard()),
            self::serviceProvider($serviceProvider, $capturedAt),
            $self,
            $receivedAt,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, $format, $nameId, $sessionIndexes],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->nameId->format,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, string, IdentityProvider, string, string, NameIdFormat, string, list<string>}>
     */
    public static function provideLogoutRequests(): iterable
    {
        yield 'for-model to saml2-model, 30 September 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt',
            self::SEPTEMBER_30,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml',
            self::modelIdentityProvider(),
            self::MODEL . 'idp/slo',
            '_b00d8f15bcc6e09626c3d388ce705bb778563bbf5e',
            NameIdFormat::Transient,
            '_a849fe5baadb7fb8e8c621c19269ce4f976adf46',
            ['_0b87387ced75ba1b87f2080d912ff64d06a11e49'],
        ];
        yield 'default-sp to its own identity provider, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml',
            self::simpleSamlPhpIdentityProvider(),
            self::IDP . 'singleLogout',
            '_464dfd53054123a49d09b10f32d28e15f7a3d3129b',
            NameIdFormat::Transient,
            '_fc87e38d42e753e675e72c83982c6b6d1e229f2d1f',
            ['_5b9957dce292a2455b0175462282c36f8023e69017'],
        ];
        yield 'for-bindings to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/slo',
            '_8355a005c7bfe4c0fd6d6b4f3f1ba61ed3c162d72a',
            NameIdFormat::Transient,
            '_8105b711c8b244b656186bf9d3410a30b97eb637',
            ['_5adee982b213afbeb74182ac727154288e401622'],
        ];
        yield 'Keycloak\'s broker to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-logoutrequest-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'slo',
            'ID_82970d1a-6f49-4556-a264-67b44245ad10',
            NameIdFormat::Persistent,
            'bindings-alice',
            ['_db380a1883610f4bb2e4a2be420aceeaeb2040e4'],
        ];
    }

    /**
     * Section 9.4, section 6.2, B-5, B-8, SAML Bindings §3.5.4
     */
    #[Test]
    #[DataProvider('provideResponseForms')]
    public function itReadsAndValidatesTheResponseFormsOfRealIdentityProviders(
        string $form,
        string $capturedAt,
        IdentityProvider $identityProvider,
        string $requestId,
        string $assertionConsumerService,
        string $audience,
        SignatureCoverage $coverage,
        string $id,
        NameIdFormat $format,
        string $relayState,
    ): void {
        // Given
        $received = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed(self::fixture($form)));

        // When
        $accepted = $received->validate(
            new ResponseValidator(SamlLoader::create(), self::clock($capturedAt), new InMemoryReplayGuard()),
            $identityProvider,
            ExpectedResponse::toRequest($requestId, $assertionConsumerService, $audience),
        );

        // Then
        static::assertSame(
            [$coverage, $id, $format, $relayState],
            [$accepted->coverage, $accepted->responseId, $accepted->assertion->nameId->format, $received->relayState],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, string, string, string, SignatureCoverage, string, NameIdFormat, string}>
     */
    public static function provideResponseForms(): iterable
    {
        yield 'SimpleSAMLphp to default-sp, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-response-form-2026-10-01.txt',
            self::OCTOBER_1_LOGIN,
            self::simpleSamlPhpIdentityProvider(),
            '_b49530d286d4adf9a5a5ca3eecbb1b5611a1f15c38',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            self::SP . 'metadata/default-sp',
            SignatureCoverage::AssertionAndResponse,
            '_218f31d51ad2954c49b68552d374ce4c9b4e5461cf',
            NameIdFormat::Transient,
            'http://localhost:8092/simplesaml/module.php/core/welcome',
        ];
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            '_41f764b4e7b601cffe0491118060eff82e63b868',
            self::BINDINGS . 'sp/acs',
            self::BINDINGS . 'sp',
            SignatureCoverage::AssertionAndResponse,
            '_f66f960182efa8c5bb823cfa34f88dc9ea47ec92dd',
            NameIdFormat::Transient,
            'bindings login ~',
        ];
        yield 'Keycloak\'s realm idp to its broker, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-response-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            'ID_ce99b63e-1c8f-4f66-bd2c-0c8fad6a8373',
            self::KEYCLOAK . 'sp/broker/idp/endpoint',
            self::KEYCLOAK . 'sp',
            SignatureCoverage::Response,
            'ID_12ee9a72-81c9-4f80-b471-a99fad65cd25',
            NameIdFormat::Persistent,
            'Y0qjsxZND40tqPcUrW6tTFVyZi6CzBonRx1z8ODFegc.nPbFjF3Rt-I.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-response-to-bindings-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            '_31f21e2eeeb8580b3de7068efc6f6a25d74c4e03',
            self::KEYCLOAK_BINDINGS_SP . 'acs',
            self::KEYCLOAK_BINDINGS_SP . 'metadata',
            SignatureCoverage::Response,
            'ID_f3af97bf-4466-4106-8f81-0128f0440904',
            NameIdFormat::Persistent,
            'bindings login ~',
        ];
    }

    /**
     * Section 9.4, section 6.1, B-2, B-5, B-8, SAML Profiles §4.4.4.1
     */
    #[Test]
    #[DataProvider('provideSignedLogoutResponseQueries')]
    public function itVerifiesAndValidatesTheSignedLogoutResponsesOverHttpRedirect(
        string $query,
        string $capturedAt,
        IdentityProvider $identityProvider,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
        string $id,
        string $relayState,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // When
        $accepted = $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock($capturedAt), new InMemoryReplayGuard()),
            $identityProvider,
            $self,
            $receivedAt,
            $requestId,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, StatusCode::Success, $relayState],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->status->code,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, ServiceProvider, string, string, string, string}>
     */
    public static function provideSignedLogoutResponseQueries(): iterable
    {
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            self::bindingsServiceProvider('sp', Binding::HttpRedirect),
            self::BINDINGS . 'sp/slo',
            '_2942fa04f07f16fa845c285b220600bf83b130c3',
            '_10f52db37594bc20921006c87338d15333d7b87d26',
            'bindings logout ~',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::keycloakBindingsServiceProvider(),
            self::KEYCLOAK_BINDINGS_SP . 'slo',
            '_8b76e5ac5b17b3f1345511b7e6fe4e1d3f927d50',
            'ID_cb3648a6-cb68-4f7e-9884-c136607e40e8',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
    }

    /**
     * Section 9.4, section 6.2, B-5, SAML Bindings §3.5.4, SAML Profiles §4.4.4.2
     */
    #[Test]
    #[DataProvider('provideLogoutResponseForms')]
    public function itReadsAndValidatesTheLogoutResponseFormsOfRealIdentityProviders(
        string $form,
        string $capturedAt,
        IdentityProvider $identityProvider,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
        string $id,
        string $relayState,
    ): void {
        // Given
        $received = new PostReceiver(SamlLoader::create())->logoutMessage(BrowserForm::parsed(self::fixture($form)));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // When
        $accepted = $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock($capturedAt), new InMemoryReplayGuard()),
            $identityProvider,
            $self,
            $receivedAt,
            $requestId,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, $id, StatusCode::Success, $relayState],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->status->code,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, ServiceProvider, string, string, string, string}>
     */
    public static function provideLogoutResponseForms(): iterable
    {
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-form-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            self::bindingsServiceProvider('sp-post', Binding::HttpPost),
            self::BINDINGS . 'sp-post/slo',
            '_403fc2f8b14e2523234555dee6caac2a86dfd0c5',
            '_0b010c354af6627fdaa9649efde479bf3809b86ba2',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
        yield 'Keycloak\'s realm idp to its broker, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::KEYCLOAK . 'sp/broker/idp/endpoint',
            'ID_30e99fe4-086c-4dc5-9e6c-02fb852eef5e',
            'ID_dc33ee08-cb71-4b1f-b627-e04427391e5a',
            'kpJCQUGfDkl7xb1GREeOsPVl',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-to-bindings-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::keycloakBindingsServiceProvider(),
            self::KEYCLOAK_BINDINGS_SP . 'slo',
            '_baa46cc0aa2b17f87c32107fb5b5dd0e89cf0c9a',
            'ID_e0a3bae3-bb0c-43fd-9bb1-3ad3b090d922',
            'bindings logout ~',
        ];
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.2, saml2-model's finding F-1
     */
    #[Test]
    #[DataProvider('provideUnsignedLogoutResponses')]
    public function itRefusesTheUnsignedLogoutResponsesOfSimpleSamlPhp(
        string $query,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock(self::OCTOBER_1), new InMemoryReplayGuard()),
            self::simpleSamlPhpIdentityProvider(),
            $self,
            $receivedAt,
            $requestId,
        );
    }

    /**
     * @return iterable<string, array{string, ServiceProvider, string, string}>
     */
    public static function provideUnsignedLogoutResponses(): iterable
    {
        yield 'to default-sp, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-unsigned-refused-query-2026-10-01.txt',
            self::serviceProvider('real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml', self::OCTOBER_1),
            self::SP . 'saml2-logout.php/default-sp',
            '_464dfd53054123a49d09b10f32d28e15f7a3d3129b',
        ];
        yield 'to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-unsigned-refused-query-2026-10-01.txt',
            self::bindingsServiceProvider('sp-defaults', Binding::HttpRedirect),
            self::BINDINGS . 'sp-defaults/slo',
            '_6a1897a87e69ff532142fe5eb169d633fcfa7362',
        ];
    }

    private static function clock(string $capturedAt): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($capturedAt));
    }

    private static function metadata(string $fixture, string $capturedAt): EntityDescriptor
    {
        return new MetadataReader(SamlLoader::create(), self::clock($capturedAt))->readTrusted(
            SamlLoader::create()->load(self::fixture($fixture)),
        );
    }

    private static function serviceProvider(string $fixture, string $capturedAt): ServiceProvider
    {
        $descriptor = self::metadata($fixture, $capturedAt);

        return $descriptor->serviceProvider ?? throw new LogicException('The metadata holds a service provider.');
    }

    private static function simpleSamlPhpIdentityProvider(): IdentityProvider
    {
        $descriptor = self::metadata('real/simplesamlphp-2.5.3.1-idp-metadata-2026-10-01.xml', self::OCTOBER_1_LOGIN);

        return $descriptor->identityProvider ?? throw new LogicException('The metadata holds an identity provider.');
    }

    private static function keycloakIdentityProvider(): IdentityProvider
    {
        $descriptor = self::metadata('real/keycloak-26.7.4-idp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1);

        return $descriptor->identityProvider ?? throw new LogicException('The metadata holds an identity provider.');
    }

    private static function keycloakBindingsIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::KEYCLOAK_BINDINGS_IDP . 'metadata',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_IDP . 'sso')],
            [new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_IDP . 'slo')],
            [NameIdFormat::Persistent],
            true,
        );
    }

    private static function keycloakBindingsServiceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            self::KEYCLOAK_BINDINGS_SP . 'metadata',
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::KEYCLOAK_BINDINGS_SP . 'acs', 0, true)]),
            [
                new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_SP . 'slo'),
                new Endpoint(Binding::HttpPost, self::KEYCLOAK_BINDINGS_SP . 'slo'),
            ],
            [NameIdFormat::Persistent],
            true,
            false,
        );
    }

    private static function modelIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::MODEL . 'idp',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/sso')],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/slo')],
            [NameIdFormat::Transient],
            true,
        );
    }

    private static function bindingsIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::BINDINGS . 'idp',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::BINDINGS . 'idp/sso')],
            [new Endpoint(Binding::HttpRedirect, self::BINDINGS . 'idp/slo')],
            [NameIdFormat::Transient],
            true,
        );
    }

    private static function bindingsServiceProvider(string $name, Binding $logout): ServiceProvider
    {
        return new ServiceProvider(
            self::BINDINGS . $name,
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::BINDINGS . $name . '/acs', 0, true)]),
            [new Endpoint($logout, self::BINDINGS . $name . '/slo')],
            [NameIdFormat::Transient],
            true,
            true,
        );
    }
}
