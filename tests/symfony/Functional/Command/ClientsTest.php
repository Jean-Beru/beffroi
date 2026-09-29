<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Command;

use Heidi\Bundle\Command\ClientDeleteCommand;
use Heidi\Bundle\Command\ClientListCommand;
use Heidi\Bundle\Command\ClientShowCommand;
use Heidi\Bundle\Doctrine\Repository\DoctrineClientRepository;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009: what a tenant manages its clients with until the tenant console. The clients of the
 * deployment and the ones that registered themselves are one list, each saying which it is, and only
 * one of the two can be taken back here.
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

    /**
     * A client that registered itself is in the same list as one the deployment declared, saying which
     * source holds it: what is listed is what is wired.
     */
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
     * RFC 7592 §2.1: what a client registered is what it reads back at its own endpoint, and it is what
     * is shown here, as the client sent it.
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
     * The same removal as the `DELETE` of RFC 7592 §2.3 and as the timed step: the row goes, and the
     * client resolves nowhere afterwards.
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
        static::assertNull(self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId));
    }

    /**
     * A declaration goes away when its block does: a command that took one out of a running process
     * would put it back at the next boot, so it is refused and the refusal says where it lives.
     */
    #[Test]
    public function aDeclaredClientIsRefusedAndStays(): void
    {
        // When
        $tester = self::console(ClientDeleteCommand::NAME, [
            'client-id' => 'oidc-demo',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('heidi.yaml', self::flattened($tester));
        static::assertNotNull(self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), 'oidc-demo'));
    }

    /**
     * Registers a client through the endpoint, so that what the console lists is what the endpoint wrote
     * and not a row a test made up.
     */
    private function register(): string
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
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode([
                'client_name' => 'A client that registered itself',
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['client_id']);
    }
}
