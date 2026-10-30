<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

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
 * RFC 7591 §2.3, the fourth mode of decision 0009: a registration authorised by a statement an authority
 * the tenant pinned signed, this provider issuing nothing. It is the mode that crosses the boundary of an
 * organisation, an initial access token being a secret this provider issues, keeps, counts and revokes for
 * every team that integrates.
 *
 * The mode is a value of one tenant's policy and the policy is read from the environment at runtime, as
 * the open mode is, so a tenant that accepts statements is a kernel this test names before it boots one.
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
     * RFC 7591 §3.2.1: a statement signed by the authority the tenant pinned registers a client, with no
     * credential of this provider presented and none held for it anywhere.
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

    /**
     * The acceptance of the issue: a client nobody here issued a credential to registers on a statement
     * alone and is a client like any other from that moment, through the whole code flow to a token.
     */
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
     * RFC 7591 §2: what the software calls itself is kept on the client, the same across every
     * installation of it, so that a product can be counted, limited and taken back across them later.
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
     * RFC 7591 §3.1.1: "values ... in the software statement MUST take precedence". It is what closes,
     * for the clients it covers, what the open mode leaves open on the consent page: the name shown is the
     * one an authority signed and never the one the caller typed.
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

    /**
     * And the page a user sees says the same, which is the whole reason the precedence is worth having.
     */
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
            // a client that registers no "scope" is registered with the one every client has
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
     * RFC 7592 §2.2 reads a replacement from what the client sends, and §3 lets the provider replace what it
     * asks for: what the statement signed outranks it as it outranked the registration (RFC 7591 §3.1.1),
     * so the name an authority signed is the one the client keeps, whatever the replacement says of it.
     *
     * @param array<string, mixed> $named what the replacement says of the name
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

    /**
     * And the page a user sees after it says the same: replacing its registration is no way for a client to
     * put a name of its own in front of the one an authority signed.
     */
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
            // a client that registers no "scope" is registered with the one every client has
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
     * Decision 0006: every refusal of a statement is the same refusal, under the code RFC 7591 §3.2.2
     * gives it, so whoever presents one learns that it was not accepted and nothing else.
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
     * RFC 7591 §2.3 and §3.1.1: one statement registers one client, whatever it is sent with the second
     * time.
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

    /**
     * A request that carries no statement at all presents nothing this mode acts on, which is the 401 of
     * a request carrying no credential and not a statement that failed to verify.
     */
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
     * What a statement says is what the client **is**; what it **may have** is the policy's. A statement
     * naming a scope the tenant hands out no token for is refused by the rule that refuses it of a request
     * body, under that rule's code and not under one of §3.2.2 about statements.
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
     * Decision 0009: a member of this provider alone is written by whoever declares a client or by the
     * registration policy of the tenant, and a statement that carries one is refused at the registration as
     * a request body that carries one is. Registered, the client would be answered 201 and then served as no
     * client, its row refused at every read.
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
     * @param array<string, mixed> $members what the client sends in the clear beside the statement
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
     * RFC 7592 §2.2: the replacement a client sends to the URI it was handed, with the token it was handed,
     * naming itself.
     *
     * @param array<string, mixed> $registered what the registration answered
     * @param array<string, mixed> $members what the client sends beside its identifier and its redirection URI
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
