<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\ClientDeleteCommand;
use App\Command\ClientListCommand;
use App\Command\ClientShowCommand;
use App\Doctrine\Repository\DoctrineClientRepository;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009
 */
final class ClientsTest extends ConsoleTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    #[Test]
    public function theListNamesAClientOfTheDeploymentAndTheSourceThatHoldsIt(): void
    {
        // When
        $tester = self::console(ClientListCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('oidc-demo', self::flattened($tester));
        static::assertStringContainsString(ConfigurationClientRepository::SOURCE, self::flattened($tester));
    }

    #[Test]
    public function theListNamesAClientThatRegisteredItselfAndTheSourceThatHoldsIt(): void
    {
        // Given
        $clientId = $this->register();

        // When
        $tester = self::console(ClientListCommand::NAME);

        // Then
        $display = self::flattened($tester);
        static::assertStringContainsString($clientId, $display);
        static::assertStringContainsString(DoctrineClientRepository::SOURCE, $display);
        static::assertStringContainsString('oidc-demo', $display);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function theControlsOfTheNameAClientRegisteredAreNotPrinted(): void
    {
        // Given
        $this->register("\e]52;c;Y3VybCBldmlsLmV4YW1wbGUvc2ggfCBzaAo=\x07\e]0;owned\x07A client");

        // When
        $tester = self::console(ClientListCommand::NAME);

        // Then
        static::assertStringContainsString(']52;c;Y3VybCBldmlsLmV4YW1wbGUvc2ggfCBzaAo=]0;ownedA client', $tester->getDisplay(true));
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function theMarkupOfTheNameAClientRegisteredIsPrintedAsText(): void
    {
        // Given
        $this->register('A client <href=https://evil.example/>docs</>');

        // When
        $tester = self::console(ClientListCommand::NAME);

        // Then
        static::assertStringContainsString('A client <href=https://evil.example/>docs</>', $tester->getDisplay(true));
    }

    /**
     * RFC 7592 §2.1
     */
    #[Test]
    public function aClientThatRegisteredItselfShowsWhatItRegistered(): void
    {
        // Given
        $clientId = $this->register();

        // When
        $tester = self::console(ClientShowCommand::NAME, [
            'client-id' => $clientId,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $display = self::flattened($tester);
        static::assertStringContainsString(self::REDIRECT_URI, $display);
        static::assertStringContainsString('A client that registered itself', $display);
    }

    #[Test]
    public function aDeclaredClientIsShownAsWhatTheConfigurationSays(): void
    {
        // When
        $tester = self::console(ClientShowCommand::NAME, [
            'client-id' => 'oidc-demo',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('declared in the configuration', self::flattened($tester));
    }

    #[Test]
    public function aClientNobodyHoldsIsSaidToBeNoClientOfTheTenant(): void
    {
        // When
        $tester = self::console(ClientShowCommand::NAME, [
            'client-id' => 'a-client-nobody-declared',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('There is no client "a-client-nobody-declared"', self::flattened($tester));
    }

    /**
     * RFC 7592 §2.3
     */
    #[Test]
    public function aClientThatRegisteredItselfIsDeleted(): void
    {
        // Given
        $clientId = $this->register();

        // When
        $tester = self::console(ClientDeleteCommand::NAME, [
            'client-id' => $clientId,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull(self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId));
    }

    #[Test]
    public function aDeclaredClientIsRefusedAndStays(): void
    {
        // When
        $tester = self::console(ClientDeleteCommand::NAME, [
            'client-id' => 'oidc-demo',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('beffroi.yaml', self::flattened($tester));
        static::assertNotNull(self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), 'oidc-demo'));
    }

    private function register(string $name = 'A client that registered itself'): string
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
                'client_name' => $name,
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['client_id']);
    }
}
