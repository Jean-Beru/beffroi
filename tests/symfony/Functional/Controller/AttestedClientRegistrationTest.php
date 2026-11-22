<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\SoftwareStatements;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7591 §2.3, Decision 0009
 */
final class AttestedClientRegistrationTest extends BrowserTestCase
{
    private const string REDIRECT_URI = 'https://attested.test/callback';

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_REGISTRATION_MODE'] = SoftwareStatementAuthorization::MODE;
        $_SERVER['BEFFROI_TEST_STATEMENT_JWKS'] = base64_encode(json_encode(
            ['keys' => ClientAssertions::publishedKeys()->keys],
            JSON_THROW_ON_ERROR,
        ));
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset(
            $_SERVER['BEFFROI_TEST_REGISTRATION_MODE'],
            $_ENV['BEFFROI_TEST_REGISTRATION_MODE'],
            $_SERVER['BEFFROI_TEST_STATEMENT_JWKS'],
            $_ENV['BEFFROI_TEST_STATEMENT_JWKS'],
        );
    }

    /**
     * RFC 7591 §3.2.1
     */
    #[Test]
    public function aStatementOfThePinnedAuthorityRegistersAClient(): void
    {
        // When
        $this->register();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));
        $registered = self::json($response);
        static::assertIsString($registered['client_id']);
        static::assertSame([self::REDIRECT_URI], $registered['redirect_uris']);
    }

    #[Test]
    public function aClientRegisteredOnAStatementSignsInEndToEnd(): void
    {
        // Given
        self::signingKey();
        $this->register([
            'scope' => 'openid profile',
        ]);
        $registered = self::json($this->browser->getResponse());
        $this->signIn(self::user('alice'));

        // When / Then
        $this->signInClient(
            self::string($registered['client_id']),
            self::REDIRECT_URI,
            self::string($registered['client_secret']),
        );
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function theSoftwareTheStatementNamesIsKeptOnTheClient(): void
    {
        // Given
        $this->register();

        // When
        $record = $this->record(self::string(self::json($this->browser->getResponse())['client_id']));

        // Then
        static::assertSame(SoftwareStatements::SOFTWARE_ID, $record?->metadata['software_id'] ?? null);
        static::assertSame('2.1.0', $record->metadata['software_version'] ?? null);
    }

    /**
     * RFC 7591 §3.1.1
     */
    #[Test]
    public function whatTheStatementSaysOutranksWhatTheClientSent(): void
    {
        // When
        $this->register([
            'client_name' => 'what the caller typed',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('Invoice reader, attested', self::json($response)['client_name']);
    }

    #[Test]
    public function theConsentPageShowsTheNameTheAuthoritySigned(): void
    {
        // Given
        $this->register([
            'client_name' => 'what the caller typed',
        ]);
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid',
        ]));
        $this->browser->request('GET', '/consent', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);

        // Then
        $page = self::string($this->browser->getResponse()->getContent());
        static::assertStringContainsString('Invoice reader, attested', $page);
        static::assertStringNotContainsString('what the caller typed', $page);
    }

    /**
     * RFC 7592 §2.2, §3, RFC 7591 §3.1.1
     *
     * @param array<string, mixed> $named
     */
    #[Test]
    #[DataProvider('provideWhatAReplacementSaysOfTheName')]
    public function aReplacementKeepsTheNameTheAuthoritySigned(array $named): void
    {
        // Given
        $this->register();
        $registered = self::json($this->browser->getResponse());

        // When
        $this->replace($registered, $named);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('Invoice reader, attested', self::json($response)['client_name'] ?? null);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideWhatAReplacementSaysOfTheName(): iterable
    {
        yield 'another name' => [[
            'client_name' => 'what the caller typed',
        ]];

        yield 'no name at all' => [[]];
    }

    #[Test]
    public function theConsentPageShowsTheNameTheAuthoritySignedAfterAReplacement(): void
    {
        // Given
        $this->register();
        $registered = self::json($this->browser->getResponse());
        $this->replace($registered, [
            'client_name' => 'what the caller typed',
        ]);
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::string($registered['client_id']), [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid',
        ]));
        $this->browser->request('GET', '/consent', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);

        // Then
        $page = self::string($this->browser->getResponse()->getContent());
        static::assertStringContainsString('Invoice reader, attested', $page);
        static::assertStringNotContainsString('what the caller typed', $page);
    }

    /**
     * Decision 0006, RFC 7591 §3.2.2
     *
     * @param array<string, mixed> $overrides
     */
    #[Test]
    #[DataProvider('provideStatementsThisTenantDoesNotAccept')]
    public function aStatementThisTenantDoesNotAcceptIsRefused(array $overrides): void
    {
        // When
        $this->register(statement: SoftwareStatements::statement(
            (string) self::tenant()->issuer,
            self::currentSecond(),
            $overrides,
        ));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_software_statement', self::json($response)['error']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideStatementsThisTenantDoesNotAccept(): iterable
    {
        yield 'signed by an authority this tenant pins nobody by' => [[
            'iss' => 'https://another-store.example.com',
        ]];
        yield 'expired' => [[
            'exp' => 1,
        ]];
        yield 'addressed to another provider' => [[
            'aud' => 'https://id.other.example',
        ]];
        yield 'carrying no identifier, so nothing can be remembered of it' => [[
            'jti' => null,
        ]];
    }

    /**
     * RFC 7591 §2.3, §3.1.1
     */
    #[Test]
    public function aStatementRegistersOneClient(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) self::tenant()->issuer, self::currentSecond());
        $this->register(statement: $statement);

        // When
        $this->register(statement: $statement);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_software_statement', self::json($response)['error']);
    }

    #[Test]
    public function aRequestThatCarriesNoStatementIsUnauthorized(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
            ], JSON_THROW_ON_ERROR),
        );

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 7591 §3.2.2
     */
    #[Test]
    public function aStatementNamingWhatTheTenantDoesNotOfferIsRefusedAsAnyMemberIs(): void
    {
        // When
        $this->register(statement: SoftwareStatements::statement(
            (string) self::tenant()->issuer,
            self::currentSecond(),
            [
                'scope' => 'openid a-scope-this-tenant-hands-out-no-token-for',
            ],
        ));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_client_metadata', self::json($response)['error']);
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aStatementCarryingAMemberOfTheDeploymentIsRefusedAsAnyMemberIs(): void
    {
        // When
        $this->register(statement: SoftwareStatements::statement(
            (string) self::tenant()->issuer,
            self::currentSecond(),
            [
                'requires_consent' => false,
            ],
        ));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_client_metadata', self::json($response)['error']);
    }

    /**
     * @param array<string, mixed> $members
     */
    private function register(array $members = [], ?string $statement = null): void
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
                ...$members,
                'software_statement' => $statement ?? SoftwareStatements::statement(
                    (string) self::tenant()->issuer,
                    self::currentSecond(),
                ),
            ], JSON_THROW_ON_ERROR),
        );
    }

    /**
     * RFC 7592 §2.2
     *
     * @param array<string, mixed> $registered
     * @param array<string, mixed> $members
     */
    private function replace(array $registered, array $members): void
    {
        $this->browser->request(
            'PUT',
            self::string($registered['registration_client_uri']),
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::string($registered['registration_access_token']),
            ],
            content: json_encode([
                'client_id' => $registered['client_id'],
                'redirect_uris' => [self::REDIRECT_URI],
                ...$members,
            ], JSON_THROW_ON_ERROR),
        );
    }

    private function record(string $clientId): ?ClientRecord
    {
        return self::service('test.beffroi.client_store', ClientStoreInterface::class)->findRecord(self::tenant(), $clientId);
    }
}
