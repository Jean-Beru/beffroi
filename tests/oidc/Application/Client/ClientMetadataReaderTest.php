<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Tests\Fixture\TextsThatAreNotPlain;
use Beffroi\Core\Tests\Fixture\RsaModuli;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\DeploymentDefaults;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidRedirectUriException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;
use function implode;
use function range;
use function sprintf;
use function str_repeat;

/**
 * RFC 7591 §2, OIDC Registration §2
 */
final class ClientMetadataReaderTest extends TestCase
{
    /**
     * RFC 7517 §5
     *
     * @var array<string, mixed>
     */
    private const array JWKS = [
        'keys' => [[
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => 'one',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]],
    ];

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheGrantOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame(['authorization_code'], array_map(static fn (object $grant): string => (string) $grant, $registration->grantTypes));
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheMethodOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame('client_secret_basic', $registration->authenticationMethod->name());
    }

    #[Test]
    public function aDeclarationThatWritesNothingTakesTheDefaultsOfADeployment(): void
    {
        // When
        $registration = Registrations::reader()->read('oidc-demo', self::declared([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]));

        // Then
        static::assertSame(
            ['authorization_code', 'refresh_token'],
            array_map(static fn (object $grant): string => (string) $grant, $registration->grantTypes),
        );
    }

    /**
     * RFC 7591 §3.1.1
     */
    #[Test]
    public function theSourceInFrontWinsTheMemberTheSourceBehindAlsoCarries(): void
    {
        // Given
        $metadata = new ClientMetadata([
            new RegisteredMembers([
                'client_name' => 'What the statement says',
            ]),
            new RegisteredMembers([
                'client_name' => 'What the client says',
                'redirect_uris' => ['https://rp.example/cb'],
            ]),
            new SpecifiedDefaults(),
        ]);

        // When
        $registration = Registrations::reader()->read('drawn', $metadata, true);

        // Then
        static::assertSame('What the statement says', $registration->presentation->name);
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function itReadsWhatAUserIsShownOfTheClient(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => 'An application',
            'client_uri' => 'https://rp.example/',
            'logo_uri' => 'https://rp.example/logo.png',
            'policy_uri' => 'https://rp.example/privacy',
            'tos_uri' => 'https://rp.example/terms',
            'contacts' => ['support@rp.example', 'support@rp.example'],
        ]);

        // Then
        static::assertSame('An application', $registration->presentation->name);
        static::assertSame('https://rp.example/', (string) $registration->presentation->uri);
        static::assertSame('https://rp.example/logo.png', (string) $registration->presentation->logoUri);
        static::assertSame('https://rp.example/privacy', (string) $registration->presentation->policyUri);
        static::assertSame('https://rp.example/terms', (string) $registration->presentation->tosUri);
        static::assertSame(['support@rp.example'], $registration->presentation->contacts);
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aClientThatRegistersNoNameIsShownUnderItsIdentifier(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertSame('drawn', $registration->presentation->name);
    }

    /**
     * OIDC Core §8, §8.1, §4
     */
    #[Test]
    public function itReadsWhatTheSubjectAndAThirdPartyLoginAreResolvedFrom(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'subject_type' => 'public',
            'sector_identifier_uri' => 'https://rp.example/sector.json',
            'initiate_login_uri' => 'https://rp.example/start',
        ]);

        // Then
        static::assertSame('public', $registration->subjectType);
        static::assertSame('https://rp.example/sector.json', (string) $registration->sectorIdentifierUri);
        static::assertSame('https://rp.example/start', (string) $registration->initiateLoginUri);
    }

    /**
     * OIDC Core §6.2, OIDC Registration §2
     */
    #[Test]
    public function aRequestUriMayCarryTheFragmentOfTheSpecification(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'request_uris' => ['https://rp.example/request.jwt#ZmFrZS1oYXNoLW9mLXRoZS1jb250ZW50'],
        ]);

        // Then
        static::assertSame(
            ['https://rp.example/request.jwt#ZmFrZS1oYXNoLW9mLXRoZS1jb250ZW50'],
            array_map(static fn (object $uri): string => (string) $uri, $registration->requestUris),
        );
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function theMembersThatAcceptPlainHttpOnALoopbackHostStillDo(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'jwks_uri' => 'http://localhost:8000/jwks.json',
            'frontchannel_logout_uri' => 'http://localhost:8000/logout',
        ]);

        // Then
        static::assertSame('http://localhost:8000/jwks.json', (string) $registration->jwksUri);
        static::assertSame('http://localhost:8000/logout', (string) $registration->frontChannelLogoutUri);
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function aClientThatRegistersNoSubjectTypeRegistersNone(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
        ]);

        // Then
        static::assertNull($registration->subjectType);
    }

    /**
     * RFC 9449 §5.2
     */
    #[Test]
    public function aClientThatAlwaysUsesDpopRegistersIt(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'dpop_bound_access_tokens' => true,
        ]);

        // When
        $registration = Registrations::reader()->read('drawn', $metadata, true);

        // Then
        static::assertTrue($registration->requiresDpopBoundTokens);
    }

    /**
     * RFC 8705 §3.4
     */
    #[Test]
    public function aClientWhoseTokensAreBoundToItsCertificateRegistersIt(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'tls_client_certificate_bound_access_tokens' => true,
        ]);

        // When
        $registration = Registrations::reader()->read('drawn', $metadata, true);

        // Then
        static::assertTrue($registration->requiresCertificateBoundTokens);
    }

    /**
     * RFC 8705 §3.4, RFC 7591 §3.2.2
     */
    #[Test]
    public function aTokenBoundToACertificateIsRefusedWhereNoMethodReadsOne(): void
    {
        // Given
        $reader = Registrations::reader(methods: new ClientAuthenticationMethods([Methods::clientSecretBasic(), Methods::none()]));
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'tls_client_certificate_bound_access_tokens' => true,
        ]);

        // When
        try {
            $reader->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame('tls_client_certificate_bound_access_tokens', $exception->member);
        }
    }

    /**
     * RFC 9101 §10.5, decision 0012
     */
    #[Test]
    public function aDeclarationThatRequiresSignedRequestObjectsAndReadsThemUnsignedIsRefused(): void
    {
        // Given
        $metadata = self::declared([
            'redirect_uris' => ['https://rp.example/cb'],
            'require_signed_request_object' => true,
            'request_object_signing_alg' => 'none',
        ]);

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('registers no request_object_signing_alg under which an unsigned one is read');

        // When
        Registrations::reader()->read('drawn', $metadata, true);
    }

    /**
     * RFC 7591 §3.2.2
     *
     * @param array<string, mixed> $members
     * @param class-string<UnreadableClientMetadataException> $refusal
     */
    #[Test]
    #[DataProvider('provideRefusedRegistrations')]
    public function aRegistrationThatDoesNotHoldTogetherIsRefusedWithTheCodeOfTheSpecification(
        array $members,
        string $refusal,
        ?string $member,
        string $message,
    ): void {
        // Given
        $metadata = self::registered($members);

        // When
        try {
            Registrations::reader()->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertInstanceOf($refusal, $exception);
            static::assertSame($member, $exception->member);
            static::assertStringContainsString($message, $exception->getMessage());
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, class-string<UnreadableClientMetadataException>, string|null, string}>
     */
    public static function provideRefusedRegistrations(): iterable
    {
        yield 'a DPoP binding that is no boolean' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'dpop_bound_access_tokens' => 'true',
            ],
            InvalidClientMetadataException::class,
            'dpop_bound_access_tokens',
            'must be a boolean',
        ];
        yield 'a member nobody reads' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'application_type' => 'web',
            ],
            InvalidClientMetadataException::class,
            null,
            'has unknown keys: application_type',
        ];
        yield 'a redirect URI with a fragment (oidcc-registration-regfrag)' => [
            [
                'redirect_uris' => ['https://rp.example/cb#part'],
            ],
            InvalidRedirectUriException::class,
            'redirect_uris',
            'must not carry a fragment',
        ];
        yield 'a logo served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'logo_uri' => 'http://rp.example/logo.png',
            ],
            InvalidClientMetadataException::class,
            'logo_uri',
            'must use HTTPS',
        ];
        yield 'a policy served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'policy_uri' => 'http://rp.example/privacy',
            ],
            InvalidClientMetadataException::class,
            'policy_uri',
            'must use HTTPS',
        ];
        yield 'terms served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'tos_uri' => 'http://rp.example/terms',
            ],
            InvalidClientMetadataException::class,
            'tos_uri',
            'must use HTTPS',
        ];
        yield 'a home page served in plain HTTP' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'client_uri' => 'http://rp.example/',
            ],
            InvalidClientMetadataException::class,
            'client_uri',
            'must use HTTPS',
        ];
        yield 'keys published inline and behind a URL' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'jwks' => self::JWKS,
                'jwks_uri' => 'https://rp.example/jwks.json',
            ],
            InvalidClientMetadataException::class,
            null,
            'either inline in "jwks" or behind a "jwks_uri", never both',
        ];
        yield 'an RSA key of 1024 bits (RFC 7518 section 3.3)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'RSA',
                        'kid' => 'weak',
                        'n' => RsaModuli::ofBits(1024),
                        'e' => 'AQAB',
                    ]],
                ],
            ],
            InvalidClientMetadataException::class,
            'jwks',
            'carries a modulus "n" of 2048 bits at least',
        ];
        yield 'a response type this provider does not answer with' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'response_types' => ['id_token token'],
            ],
            InvalidClientMetadataException::class,
            'response_types',
            'response_types option of the client "drawn" must be one of: code',
        ];
        yield 'a scope that is no scope token' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'scope' => 'openid "quoted"',
            ],
            InvalidClientMetadataException::class,
            'scope',
            'is not a scope token',
        ];
        yield 'a kind of subject this provider assigns none' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'subject_type' => 'pairwise',
            ],
            InvalidClientMetadataException::class,
            'subject_type',
            'subject_type option of the client "drawn" must be one of: public',
        ];
        yield 'a redirection URI that carries a fragment (oidcc-redirect-uri-regfrag)' => [
            [
                'redirect_uris' => ['https://rp.example/cb#frag'],
            ],
            InvalidRedirectUriException::class,
            'redirect_uris',
            'must not carry a fragment',
        ];
        yield 'a login begun by a third party over plain HTTP (oidcc-3rd_party-init-login-nohttps)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'initiate_login_uri' => 'http://rp.example/start',
            ],
            InvalidClientMetadataException::class,
            'initiate_login_uri',
            'must use HTTPS, on a loopback host as anywhere else',
        ];
        yield 'a login begun by a third party over plain HTTP on a loopback host' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'initiate_login_uri' => 'http://localhost:8443/test/a/beffroi/initiate-login',
            ],
            InvalidClientMetadataException::class,
            'initiate_login_uri',
            'must use HTTPS, on a loopback host as anywhere else',
        ];
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function aKindOfSubjectTheProviderAssignsIsRegistered(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
        ]);

        // When
        $registration = Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);

        // Then
        static::assertSame('pairwise', $registration->subjectType);
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function aClientOfAKindThatNeedsASectorAndNamesNoneIsRefused(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://one.example/cb', 'https://other.example/cb'],
            'token_endpoint_auth_method' => 'none',
            'subject_type' => 'pairwise',
        ]);

        // When
        try {
            Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);
            static::fail('The registration was read.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame('sector_identifier_uri', $exception->member);
            static::assertStringContainsString('registers redirection and login URIs on one.example and other.example', $exception->getMessage());
        }
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aClientThatRegistersNoKindNamesNone(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // When
        $registration = Registrations::reader(subjects: Subjects::bothKinds())->read('drawn', $metadata);

        // Then
        static::assertNull($registration->subjectType);
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aResponseTypeNoGrantOfTheRegistrationAnswersWithIsRefused(): void
    {
        // Given
        $metadata = self::registered([
            'grant_types' => ['client_credentials'],
            'response_types' => ['code'],
        ]);

        // When
        try {
            Registrations::reader(grants: Grants::servedWithClientCredentials())->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertSame('response_types', $exception->member);
            static::assertStringContainsString('registers the response type "code" and no grant that would answer with one', $exception->getMessage());
        }
    }

    #[Test]
    public function aRefusalSaysWhichSourceCarriedTheValue(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'logo_uri' => 'http://rp.example/logo.png',
        ]);

        // When
        try {
            Registrations::reader()->read('drawn', $metadata, true);
            static::fail('The registration was read.');
        } catch (UnreadableClientMetadataException $exception) {
            // Then
            static::assertSame('the registration the client sent', $exception->source);
        }
    }

    #[Test]
    public function aGrantNothingServesIsRefusedInARegistrationAsInADeclaration(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'grant_types' => ['client_credentials'],
        ]);

        // Then
        $this->expectException(UnreadableClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('must be one of: authorization_code, refresh_token');

        // When
        Registrations::reader()->read('drawn', $metadata);
    }

    /**
     * RFC 7591 §2, §3.2.1
     */
    #[Test]
    public function aMethodThatProvesASecretNeedsTheProviderToHoldOne(): void
    {
        // Given
        $metadata = self::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        $this->expectException(UnreadableClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('therefore needs a secret');

        // When
        Registrations::reader()->read('drawn', $metadata);
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNotPlainText')]
    public function aNameThatIsNotPlainTextIsRefused(string $name): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('must be plain text of at most 100 characters');

        // When
        self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => $name,
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNotPlainText(): iterable
    {
        yield 'a line feed' => ["Acme\n\nYour account is locked, call +33 1 23 45 67 89"];
        yield 'a right-to-left override' => ["Acme \u{202E}gnp.exe"];
        yield 'a zero-width space' => ["Ac\u{200B}me"];
        yield 'a line separator' => ["Acme\u{2028}Your account is locked"];
        yield 'a hundred and one characters' => [str_repeat('é', ClientMetadataReader::MAX_NAME_LENGTH + 1)];
    }

    /**
     * OIDC Registration §2
     */
    #[Test]
    public function aNameOfAHundredCharactersIsRead(): void
    {
        // Given
        $name = 'Ministère de l’Intérieur ' . str_repeat('é', ClientMetadataReader::MAX_NAME_LENGTH - 25);

        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'client_name' => $name,
        ]);

        // Then
        static::assertSame($name, $registration->presentation->name);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aRegisteredListOfMoreThanAHundredValuesIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The redirect_uris option of the client "drawn" lists 100 values at most.');

        // When
        self::read([
            'redirect_uris' => self::uris(ClientMetadataReader::MOST_VALUES + 1),
        ]);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    #[DataProvider('provideLists')]
    public function aDeclaredListOfMoreThanAHundredValuesIsRefused(string $member): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs(sprintf('The %s option of the client "drawn" lists 100 values at most.', $member));

        // When
        Registrations::reader()->read(
            'drawn',
            self::declared([
                'redirect_uris' => ['https://rp.example/cb'],
                $member => self::uris(ClientMetadataReader::MOST_VALUES + 1),
            ]),
            true,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLists(): iterable
    {
        yield 'redirect_uris' => ['redirect_uris'];
        yield 'post_logout_redirect_uris' => ['post_logout_redirect_uris'];
        yield 'request_uris' => ['request_uris'];
        yield 'contacts' => ['contacts'];
        yield 'grant_types' => ['grant_types'];
        yield 'response_types' => ['response_types'];
        yield 'resources' => ['resources'];
        yield 'authorization_details_types' => ['authorization_details_types'];
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aListOfAHundredValuesIsRead(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => self::uris(ClientMetadataReader::MOST_VALUES),
        ]);

        // Then
        static::assertCount(ClientMetadataReader::MOST_VALUES, $registration->redirectUris);
    }

    /**
     * RFC 7591 §2, RFC 6749 §3.3
     */
    #[Test]
    public function aScopeOfMoreThanAHundredScopesIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('names 100 scopes at most');

        // When
        self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => implode(' ', array_map(static fn (int $index): string => 'scope.' . $index, range(1, 101))),
        ]);
    }

    #[Test]
    public function aRegistrationWhoseSecretTheProviderHoldsIsRead(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        // Then
        static::assertTrue($registration->registersASecret);
    }

    /**
     * RFC 7591 §5
     */
    #[Test]
    #[DataProvider('providePages')]
    public function aPageTheClientRegistersOnTheHostOfItsRedirectionIsShown(string $member): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            $member => 'https://rp.example/' . $member,
        ]);

        // Then
        static::assertSame('https://rp.example/' . $member, (string) self::pageOf($registration, $member));
    }

    /**
     * RFC 7591 §5
     */
    #[Test]
    #[DataProvider('providePages')]
    public function aPageTheClientRegistersOnAnotherHostIsReadAsNone(string $member): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            $member => 'https://cdn.rp.example/' . $member,
        ]);

        // Then
        static::assertNull(self::pageOf($registration, $member));
    }

    /**
     * RFC 7591 §5
     */
    #[Test]
    #[DataProvider('providePages')]
    public function aPageADeploymentDeclaresOnAnotherHostIsShown(string $member): void
    {
        // When
        $registration = Registrations::reader()->read(
            'declared',
            new ClientMetadata([
                new DeclaredMembers([
                    'redirect_uris' => ['https://rp.example/cb'],
                    $member => 'https://cdn.rp.example/' . $member,
                ]),
                new DeploymentDefaults(),
            ]),
            true,
        );

        // Then
        static::assertSame('https://cdn.rp.example/' . $member, (string) self::pageOf($registration, $member));
    }

    /**
     * RFC 7591 §2.3, §5
     */
    #[Test]
    #[DataProvider('providePages')]
    public function aPageAnAuthorityAttestsOnAnotherHostIsShown(string $member): void
    {
        // When
        $registration = Registrations::reader()->read(
            'attested',
            new ClientMetadata([
                new AttestedMembers([
                    $member => 'https://cdn.rp.example/' . $member,
                ]),
                new RegisteredMembers([
                    'redirect_uris' => ['https://rp.example/cb'],
                ]),
                new SpecifiedDefaults(),
            ]),
            true,
        );

        // Then
        static::assertSame('https://cdn.rp.example/' . $member, (string) self::pageOf($registration, $member));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePages(): iterable
    {
        yield 'its logo' => ['logo_uri'];
        yield 'its home page' => ['client_uri'];
        yield 'its policy' => ['policy_uri'];
        yield 'its terms' => ['tos_uri'];
    }

    private static function pageOf(ClientRegistration $registration, string $member): ?ClientUri
    {
        $presentation = $registration->presentation;

        return match ($member) {
            'logo_uri' => $presentation->logoUri,
            'client_uri' => $presentation->uri,
            'policy_uri' => $presentation->policyUri,
            default => $presentation->tosUri,
        };
    }

    /**
     * RFC 7591 §2, §3.2.1
     *
     * @param array<string, mixed> $members
     */
    private static function read(array $members): ClientRegistration
    {
        return Registrations::reader()->read('drawn', self::registered($members), true);
    }

    /**
     * @return list<string>
     */
    private static function uris(int $count): array
    {
        return array_map(static fn (int $index): string => 'https://rp.example/cb/' . $index, range(1, $count));
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function registered(array $members): ClientMetadata
    {
        return Registrations::registered($members);
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function declared(array $members): ClientMetadata
    {
        return Registrations::declared($members);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    #[DataProvider('provideSoftwareThatIsNotPlainText')]
    public function aSoftwareMemberThatIsNotPlainTextIsRefused(string $member, string $value): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains(sprintf('The %s option of the client', $member));

        // When
        self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            $member => $value,
        ]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSoftwareThatIsNotPlainText(): iterable
    {
        foreach (['software_id', 'software_version'] as $member) {
            foreach (TextsThatAreNotPlain::around('4.2') as $case => [$value]) {
                yield $member . ', ' . $case => [$member, $value];
            }
            yield $member . ', longer than a line may be' => [$member, str_repeat('a', 256)];
        }
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    #[DataProvider('provideContactsThatAreNotPlainText')]
    public function aContactThatIsNotPlainTextIsRefused(string $contact): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('must list plain texts of at most 255 characters');

        // When
        self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'contacts' => ['support@rp.example', $contact],
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideContactsThatAreNotPlainText(): iterable
    {
        yield from TextsThatAreNotPlain::around('ops@rp.example');
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function theSoftwareOfAClientIsReadAsItWrote(): void
    {
        // When
        $registration = self::read([
            'redirect_uris' => ['https://rp.example/cb'],
            'software_id' => '4NRB1-0XZABZI9E6-5SM3R',
            'software_version' => '2.1 (build 2026-11-23)',
        ]);

        // Then
        static::assertSame('4NRB1-0XZABZI9E6-5SM3R', $registration->softwareId);
        static::assertSame('2.1 (build 2026-11-23)', $registration->softwareVersion);
    }
}
