<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use App\Message\RemoveUnusedClients;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009: a client that registered itself carries the date of its last use, and the timed step drops
 * the ones nobody uses any more. Clients that are never cleaned up are a table that only grows and, worse,
 * "redirect_uris" nobody watches any more.
 */
final class UnusedClientFlowTest extends BrowserTestCase
{
    private const string INITIAL_ACCESS_TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * @var array<string, mixed>
     */
    private array $registered = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->issue();
        $this->registered = $this->register();
    }

    /**
     * A client that has only registered itself has used nothing, which is not the same as one used long ago
     * and is not kept for as long.
     */
    #[Test]
    public function aClientThatOnlyRegisteredItselfHasUsedNothing(): void
    {
        // When
        $record = $this->record();

        // Then
        static::assertNull($record?->lastUsedAt);
    }

    /**
     * The two things that mean somebody is using a client: an authorization granted for it, and a request it
     * made at the token endpoint. Both are played here through the flow that raises them.
     */
    #[Test]
    #[DataProvider('provideUses')]
    public function aUseMovesTheDateOfTheLastOne(bool $exchangeTheCode): void
    {
        // Given
        self::signingKey();
        $clientId = self::string($this->registered['client_id']);

        // When
        $code = $this->codeAllowedByAlice($clientId);
        if ($exchangeTheCode) {
            $this->exchange($clientId, $code);
        }

        // Then
        self::reload();
        static::assertNotNull($this->record()?->lastUsedAt);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideUses(): iterable
    {
        yield 'an authorization granted for the client' => [false];

        yield 'a request the client made at the token endpoint' => [true];
    }

    /**
     * A request served for another client is not a use of this one.
     */
    #[Test]
    public function aRequestOfAnotherClientLeavesThisOneAlone(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // Then
        self::reload();
        static::assertNull($this->record()?->lastUsedAt);
    }

    /**
     * Decision 0009: on the clock of the kernel, a client that was never used is there one instant before the
     * shorter duration its policy names.
     */
    #[Test]
    public function aClientNobodyEverUsedIsThereUntilTheDurationItsPolicyNames(): void
    {
        // Given
        self::mockTime(self::currentSecond()->add(new ClientRegistrationPolicy('a-mode')->keepsAClientNeverUsedFor)->modify('-1 minute'));

        // When
        $this->runTheStep();

        // Then
        static::assertNotNull($this->record());
    }

    #[Test]
    public function aClientNobodyEverUsedIsGoneAfterIt(): void
    {
        // Given
        self::mockTime(self::currentSecond()->add(new ClientRegistrationPolicy('a-mode')->keepsAClientNeverUsedFor)->modify('+1 minute'));

        // When
        $this->runTheStep();

        // Then
        static::assertNull($this->record());
    }

    /**
     * Decision 0009: a client a deployment declared in its configuration is never deleted, whatever the dates
     * say. It has no row at all, so there is nothing for the step to read and no condition in it about them.
     */
    #[Test]
    public function aClientTheDeploymentDeclaredIsNeverTouched(): void
    {
        // Given
        self::mockTime(self::currentSecond()->modify('+10 years'));

        // When
        $this->runTheStep();

        // Then
        self::reload();
        static::assertNotNull(
            self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), 'oidc-demo'),
        );
    }

    /**
     * RFC 7592 §2.3 asks that what a client held be invalidated with it, and this is how: a record whose
     * client no longer resolves is a record nobody finds, so a refresh token of a deleted client is a refresh
     * token nobody may spend. The row is left where it is, which is the state this issue decides.
     */
    #[Test]
    public function aRefreshTokenOfADeletedClientCannotBeSpent(): void
    {
        // Given
        self::signingKey();
        $clientId = self::string($this->registered['client_id']);
        $secret = self::string($this->registered['client_secret']);
        $this->exchange($clientId, $this->codeAllowedByAlice($clientId));
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token']);
        self::mockTime(self::currentSecond()->modify('+10 years'));
        $this->runTheStep();
        static::assertNull($this->record());

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    private function runTheStep(): void
    {
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new RemoveUnusedClients());
        self::reload();
    }

    private function record(): ?ClientRecord
    {
        return self::service('test.beffroi.client_store', ClientStoreInterface::class)
            ->findRecord(self::tenant(), self::string($this->registered['client_id']));
    }

    private function issue(): void
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::INITIAL_ACCESS_TOKEN),
                'The team that integrates',
                1,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }

    /**
     * @return array<string, mixed>
     */
    private function register(): array
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::INITIAL_ACCESS_TOKEN,
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['authorization_code', 'refresh_token'],
                'scope' => 'openid profile offline_access',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    private function exchange(string $clientId, string $code): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . self::string($this->registered['client_secret'])),
            ],
        );
    }

    private function codeAllowedByAlice(string $clientId): string
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid profile offline_access',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }
}
