<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\InventedClaimsProvider;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #920: the scope of an API stands for no claim, and a deployment that declares no client declares it for its
 * tenant, which then hands out tokens for it: its document announces it, a client that registers itself may register
 * it (decision 0009), and that client is granted it at the authorization endpoint. A deployment of the image declares
 * no client (decision 0030), so this is how the relying party it serves is given the scope of its API.
 *
 * The scopes of the tenant are read from the environment at runtime, so a tenant that declares some is a kernel this
 * test names them for before it boots one.
 */
final class DeclaredScopeRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    protected function setUp(): void
    {
        // two scopes of an API that no claims provider serves and no client of this kernel registers
        $_SERVER['BEFFROI_TEST_TENANT_SCOPES'] = json_encode(['payroll.read', 'payroll.write'], JSON_THROW_ON_ERROR);
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_TENANT_SCOPES'], $_ENV['BEFFROI_TEST_TENANT_SCOPES']);
    }

    /**
     * OIDC Discovery §3: a client learns from the document which scopes exist, so a scope the deployment declares is
     * announced before any client registers it, after what the claims providers serve and before what the clients of
     * the tenant registered.
     */
    #[Test]
    public function theDocumentAnnouncesTheScopesTheDeploymentDeclares(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(
            [
                'openid',
                'profile',
                'email',
                'address',
                'phone',
                InventedClaimsProvider::SCOPE,
                'payroll.read',
                'payroll.write',
                'invoices.read',
                'invoices.write',
                'offline_access',
            ],
            self::json($this->browser->getResponse())['scopes_supported'],
        );
    }

    /**
     * Decision 0009: a client that registers itself is held to what its tenant offers, and a scope the deployment
     * declares is offered, so the registration that names one is written as it was sent (RFC 7591 §3.2.1).
     */
    #[Test]
    public function aClientThatRegistersItselfMayRegisterAScopeTheDeploymentDeclares(): void
    {
        // When
        $registered = $this->register('openid payroll.read');

        // Then
        static::assertSame('openid payroll.read', $registered['scope']);
    }

    /**
     * OIDC Core §3.1.2.1: the client so registered asks for the scope at the authorization endpoint, and the request
     * ends with a code rather than with "invalid_scope".
     */
    #[Test]
    public function suchAClientIsGrantedTheScopeAtTheAuthorizationEndpoint(): void
    {
        // Given
        $registered = $this->register('openid payroll.read');
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::string($registered['client_id']), [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid payroll.read',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        // Then
        static::assertIsString(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    /**
     * The registration of RFC 7591 §3.1, authorised by an initial access token the tenant issued (§1.2).
     *
     * @return array<string, mixed>
     */
    private function register(string $scope): array
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
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
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => $scope,
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }
}
