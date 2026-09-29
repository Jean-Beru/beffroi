<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §2: "If omitted, an authorization server MAY register a client with a default set of scopes."
 * The set belongs to the registration policy of the tenant, is written on the registration at the moment
 * that policy creates it, and is read back from the row that kept it. A client that names its own scopes
 * keeps them.
 *
 * It is what the modules `oidcc-refresh-token` and `-refresh-token-rp-key-rotation` need: the registration
 * request of every module of the Dynamic OP plan carries no `scope` member at all, and those two then ask
 * for `openid offline_access` at the authorization endpoint.
 *
 * The policy of the tenant is read from the environment at runtime, the way the load budgets are, so that
 * a tenant carrying a default set of scopes is a kernel this test names before it boots one.
 */
final class DefaultScopeRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * What the tenant of this test hands out, among the scopes it announces: the two of a client that signs
     * a user in, and the one that buys a refresh token (OIDC Core §11).
     */
    private const string DEFAULT_SCOPE = 'openid profile offline_access';

    protected function setUp(): void
    {
        $_SERVER['HEIDI_TEST_REGISTRATION_DEFAULT_SCOPE'] = self::DEFAULT_SCOPE;
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['HEIDI_TEST_REGISTRATION_DEFAULT_SCOPE'], $_ENV['HEIDI_TEST_REGISTRATION_DEFAULT_SCOPE']);
    }

    /**
     * RFC 7591 §2: a registration that names no scope is registered with what its tenant wrote, and not
     * with the "openid" a registration takes when nobody says otherwise.
     */
    #[Test]
    public function aClientThatRegistersNoScopeTakesWhatTheTenantWrote(): void
    {
        // Given
        $registered = $this->register([]);
        self::reload();

        // When
        $client = self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), self::string($registered['client_id']));

        // Then
        static::assertSame(self::DEFAULT_SCOPE, (string) $client?->registration->allowedScopes);
    }

    /**
     * A client that names its own scopes keeps them, at the registration and at every read of the row
     * afterwards: what the policy writes is what the registration did not say.
     */
    #[Test]
    public function aClientThatNamesItsOwnScopeKeepsIt(): void
    {
        // Given
        $registered = $this->register([
            'scope' => 'openid',
        ]);
        self::reload();

        // When
        $client = self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), self::string($registered['client_id']));

        // Then
        static::assertSame('openid', (string) $client?->registration->allowedScopes);
    }

    /**
     * `oidcc-refresh-token`: the client the plan registers names no scope and then asks for
     * `openid offline_access`, which a client registered for "openid" alone is refused with
     * `invalid_scope`.
     */
    #[Test]
    public function suchAClientMayAskForTheScopesTheTenantWrote(): void
    {
        // Given
        $registered = $this->register([
            'grant_types' => ['authorization_code', 'refresh_token'],
        ]);
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::string($registered['client_id']), [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid offline_access',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        // Then
        static::assertIsString(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    /**
     * @param array<string, mixed> $members
     *
     * @return array<string, mixed>
     */
    private function register(array $members): array
    {
        $this->issue();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode(
                $members
                + [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    private function issue(): void
    {
        self::service('test.heidi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::TOKEN),
                'The team that integrates',
                1,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }
}
