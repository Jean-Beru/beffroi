<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Bundle\Message\RemoveUnusedClients;
use Heidi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Port\ClientStoreInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * RFC 7591 §1.3, decision 0009: the mode built second. The tenant registers whoever asks, with no
 * credential presented at all, which is what the `dynamic_client` variant of the conformance suite sends.
 *
 * The same request is a 401 on the tenant of the controlled mode (`ClientRegistrationTest`) and a 404 on a
 * closed one (`ClosedClientRegistrationTest`): the mode is a value of one tenant's policy, and the policy
 * of the tenant is read from the environment at runtime, the way the load budgets are, so that a tenant
 * open to strangers is a kernel this test names before it boots one.
 */
final class OpenClientRegistrationTest extends BrowserTestCase
{
    private const string REDIRECT_URI = 'https://a-stranger.test/callback';

    protected function setUp(): void
    {
        $_SERVER['HEIDI_TEST_REGISTRATION_MODE'] = OpenRegistrationAuthorization::MODE;
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['HEIDI_TEST_REGISTRATION_MODE'], $_ENV['HEIDI_TEST_REGISTRATION_MODE']);
    }

    /**
     * RFC 7591 §3.2.1: what this mode changes is that nothing authorises; what it registers and what it
     * answers are what any other mode registers and answers.
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
     * Nothing comes before the metadata on this tenant, so a request that carries none is told that and
     * not something about a credential it was never asked for (RFC 7591 §3.1).
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
     * Decision 0009: a client nobody authorised gets nothing a declared client does not get, and is
     * refused what a declared client is refused. The same request is made of both, and the two answers
     * are the same answer.
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
     * Decision 0009: a client a stranger registered and nobody ever used is on the purge every other
     * registered client is on, at the duration its tenant's policy names. A conformance run leaves one
     * behind on every module, and the tenant that carries this mode names a short one for that reason.
     */
    #[Test]
    public function aClientNobodyAuthorisedIsGoneAfterTheDurationItsPolicyNames(): void
    {
        // Given
        $this->register();
        $clientId = self::string(self::json($this->browser->getResponse())['client_id']);
        self::mockTime(self::currentSecond()->add(new ClientRegistrationPolicy('a-mode')->keepsAClientNeverUsedFor)->modify('+1 minute'));

        // When
        self::service('test.heidi.command_bus', MessageBusInterface::class)->dispatch(new RemoveUnusedClients());
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
        return self::service('test.heidi.client_store', ClientStoreInterface::class)->findRecord(self::tenant(), $clientId);
    }

    /**
     * RFC 6749 §3.3: a scope the client did not register is not its to ask for, and what comes back is a
     * redirection carrying the refusal.
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
