<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Message\RemoveUnusedClients;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Port\ClientStoreInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * RFC 7591 §1.3, Decision 0009
 */
final class OpenClientRegistrationTest extends BrowserTestCase
{
    private const string REDIRECT_URI = 'https://a-stranger.test/callback';

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_REGISTRATION_MODE'] = OpenRegistrationAuthorization::MODE;
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_REGISTRATION_MODE'], $_ENV['BEFFROI_TEST_REGISTRATION_MODE']);
    }

    /**
     * RFC 7591 §3.2.1
     */
    #[Test]
    public function aClientThatPresentsNothingIsRegistered(): void
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
     * RFC 7591 §3.1
     */
    #[Test]
    public function aBodyThatIsNoJsonObjectIsWhatRefusesFirst(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
            ],
            content: 'not a JSON object',
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame(
            'The body of a registration request is a JSON object (RFC 7591 section 3.1).',
            self::json($response)['error_description'],
        );
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aClientNobodyAuthorisedIsRefusedWhatADeclaredClientIsRefused(): void
    {
        // Given
        $this->register();
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);
        $this->signIn(self::user('alice'));

        // When
        $registered = $this->askForAScopeNobodyRegistered($clientId, self::REDIRECT_URI);
        $declared = $this->askForAScopeNobodyRegistered('native-app', 'http://127.0.0.1/callback');

        // Then
        static::assertSame($declared, $registered);
        static::assertSame('invalid_scope', $registered['error'] ?? null);
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aClientNobodyAuthorisedIsGoneAfterTheDurationItsPolicyNames(): void
    {
        // Given
        $this->register();
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);
        self::mockTime(self::currentSecond()->add(new ClientRegistrationPolicy('a-mode')->keepsAClientNeverUsedFor)->modify('+1 minute'));

        // When
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new RemoveUnusedClients());
        self::reload();

        // Then
        static::assertNull($this->record($clientId));
    }

    private function register(): void
    {
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
    }

    private function record(string $clientId): ?ClientRecord
    {
        return self::service('test.beffroi.client_store', ClientStoreInterface::class)->findRecord(self::tenant(), $clientId);
    }

    /**
     * RFC 6749 §3.3
     *
     * @return array<string, string>
     */
    private function askForAScopeNobodyRegistered(string $clientId, string $redirectUri): array
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
            'scope' => 'openid address',
        ]));
        $query = self::redirectedQuery($this->browser->getResponse());
        unset($query['iss']);

        return $query;
    }
}
