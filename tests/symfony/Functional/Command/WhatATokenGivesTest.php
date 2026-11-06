<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\ClientShowCommand;
use App\Command\ClientTokenIssueCommand;
use App\Command\ClientTokenListCommand;
use function base64_encode;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7591 §1.2, Decision 0043
 */
final class WhatATokenGivesTest extends ConsoleTestCase
{
    private const string NAME = 'The team of the invoices';

    private const string INVOICES = 'https://invoices.test/';

    /**
     * RFC 6749 §4.4, RFC 8707 §2
     */
    #[Test]
    public function aClientATokenGaveAnApiGetsATokenOfItsOwnAddressedToIt(): void
    {
        // Given
        $registered = $this->register(self::valueOf($this->issue([
            '--resource' => [self::INVOICES],
        ])));

        // When
        $this->ask($registered);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(self::INVOICES, self::claimsOf(self::string(self::json($response)['access_token']))['aud']);
    }

    /**
     * RFC 9728 §4
     */
    #[Test]
    public function theDocumentAnnouncesTheApiATokenGaveOnceAClientHoldsIt(): void
    {
        // Given
        $this->register(self::valueOf($this->issue([
            '--resource' => [self::INVOICES],
        ])));

        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $announced = self::json($this->browser->getResponse())['protected_resources'] ?? null;
        static::assertIsArray($announced);
        static::assertContains(self::INVOICES, $announced);
    }

    /**
     * RFC 7592 §2.2
     */
    #[Test]
    public function aClientThatReplacesItsRegistrationKeepsTheApiItWasGiven(): void
    {
        // Given
        $registered = $this->register(self::valueOf($this->issue([
            '--resource' => [self::INVOICES],
        ])));
        $this->replace($registered);

        // When
        $this->ask($registered);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(self::INVOICES, self::claimsOf(self::string(self::json($response)['access_token']))['aud']);
    }

    #[Test]
    public function aTokenThatGivesTheOpaqueShapeHasItsClientsHoldOpaqueTokens(): void
    {
        // Given
        $registered = $this->register(self::valueOf($this->issue([
            '--resource' => [self::INVOICES],
            '--access-token-format' => 'opaque',
        ])));

        // When
        $this->ask($registered);

        // Then
        static::assertTrue(DrawnSecret::isValue(self::string(self::json($this->browser->getResponse())['access_token'])));
    }

    #[Test]
    public function issuingATokenSaysWhatItGives(): void
    {
        // When
        $tester = $this->issue([
            '--resource' => [self::INVOICES],
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('resources: ["https://invoices.test/"]', self::flattened($tester));
    }

    #[Test]
    public function theListSaysWhatEachTokenGives(): void
    {
        // Given
        $this->issue([
            '--resource' => [self::INVOICES],
        ]);

        // When
        $tester = self::console(ClientTokenListCommand::NAME);

        // Then
        static::assertStringContainsString('resources: ["https://invoices.test/"]', self::flattened($tester));
    }

    #[Test]
    public function aClientSaysWhatItsTokenGaveIt(): void
    {
        // Given
        $registered = $this->register(self::valueOf($this->issue([
            '--resource' => [self::INVOICES],
        ])));

        // When
        $tester = self::console(ClientShowCommand::NAME, [
            'client-id' => self::string($registered['client_id']),
        ]);

        // Then
        $display = self::flattened($tester);
        static::assertStringContainsString('Given by the initial access token', $display);
        static::assertStringContainsString('["https://invoices.test/"]', $display);
    }

    #[Test]
    public function aTokenThatWouldGiveAShapeThisProviderDoesNotIssueIsNotIssued(): void
    {
        // When
        $tester = $this->issue([
            '--access-token-format' => 'paseto',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The access_token_format option of the client "The team of the invoices" must be one of:', self::flattened($tester));
    }

    /**
     * RFC 8693 §2.1
     */
    #[Test]
    public function aTokenThatLetsItsClientsExchangeTheTokenOfAPersonNamesWhatTheyExchange(): void
    {
        // When
        $tester = $this->issue([
            '--exchange-for-a-user' => true,
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('--exchange-subject-token-type', self::flattened($tester));
    }

    /**
     * @param array<string, bool|string|list<string>> $options
     */
    private function issue(array $options): CommandTester
    {
        return self::console(ClientTokenIssueCommand::NAME, [
            'name' => self::NAME,
            ...$options,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function register(string $token): array
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
            ],
            content: json_encode(self::members(), JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    /**
     * RFC 7592 §2.2
     *
     * @param array<string, mixed> $registered
     */
    private function replace(array $registered): void
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
                'client_secret' => $registered['client_secret'],
                ...self::members(),
                'client_name' => 'The invoices, renamed',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
    }

    /**
     * @return array<string, mixed>
     */
    private static function members(): array
    {
        return [
            'grant_types' => ['client_credentials'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => 'invoices.read',
        ];
    }

    /**
     * @param array<string, mixed> $registered
     */
    private function ask(array $registered): void
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
            ],
        );
    }
}
