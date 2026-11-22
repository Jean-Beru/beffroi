<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 9449 §5.2
 */
final class DpopBoundRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string INVOICES = 'https://invoices.test/';

    #[Test]
    public function aClientRegistersThatItAlwaysUsesDpop(): void
    {
        // When
        $registered = $this->register();

        // Then
        static::assertTrue($registered['dpop_bound_access_tokens'] ?? null);
    }

    #[Test]
    public function aTokenRequestOfSuchAClientThatCarriesNoProofIsRefused(): void
    {
        // Given
        $registered = $this->register();

        // When
        $this->ask($registered);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('invalid_request', self::json($response)['error'] ?? null);
    }

    #[Test]
    public function aTokenRequestOfSuchAClientThatProvesAKeyGetsATokenBoundToIt(): void
    {
        // Given
        $registered = $this->register();

        // When
        $this->ask($registered, Proofs::proof('POST', 'https://op.test/token', Clock::get()->now()));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('DPoP', self::json($response)['token_type'] ?? null);
    }

    /**
     * @return array<string, mixed>
     */
    private function register(): array
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
                new GrantedMembers([
                    'resources' => [self::INVOICES],
                ]),
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
                'grant_types' => ['client_credentials'],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => 'invoices.read',
                'dpop_bound_access_tokens' => true,
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    /**
     * @param array<string, mixed> $registered
     */
    private function ask(array $registered, ?string $proof = null): void
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => self::INVOICES,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode(self::string($registered['client_id']) . ':' . self::string($registered['client_secret'])),
                ...($proof === null ? [] : ['HTTP_DPOP' => $proof]),
            ],
        );
    }
}
