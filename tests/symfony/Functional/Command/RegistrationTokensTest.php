<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\ClientTokenIssueCommand;
use App\Command\ClientTokenListCommand;
use App\Command\ClientTokenRevokeCommand;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, decision 0009
 */
final class RegistrationTokensTest extends ConsoleTestCase
{
    private const string NAME = 'The team that integrates';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    #[Test]
    public function issuingATokenPrintsItsValueOnce(): void
    {
        // When
        $tester = $this->issue();

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertTrue(DrawnSecret::isValue(self::valueOf($tester)));
    }

    #[Test]
    public function theListSaysWhatATokenIsWorthAndNeverWhatItIs(): void
    {
        // Given
        $value = self::valueOf($this->issue());

        // When
        $tester = self::console(ClientTokenListCommand::NAME);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $display = self::flattened($tester);
        static::assertStringContainsString(self::NAME, $display);
        static::assertStringContainsString('authorises a registration', $display);
        static::assertStringNotContainsString($value, $display);
    }

    #[Test]
    public function aTenantThatIssuedNothingIsSaidToHaveIssuedNothing(): void
    {
        // When
        $tester = self::console(ClientTokenListCommand::NAME);

        // Then
        static::assertStringContainsString('has issued no initial access token', self::flattened($tester));
    }

    #[Test]
    public function aTokenTheConsoleIssuedRegistersAClient(): void
    {
        // Given
        $value = self::valueOf($this->issue());

        // When
        $this->register($value);

        // Then
        static::assertSame(Response::HTTP_CREATED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aTokenTheConsoleRevokedRegistersNobody(): void
    {
        // Given
        $issued = $this->issue(registrations: 5);
        $value = self::valueOf($issued);

        // When
        $tester = self::console(ClientTokenRevokeCommand::NAME, [
            'id' => self::displayed($issued, 'Id'),
        ]);
        $this->register($value);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aRevokedTokenIsListedAsTakenBack(): void
    {
        // Given
        self::console(ClientTokenRevokeCommand::NAME, [
            'id' => self::displayed($this->issue(), 'Id'),
        ]);

        // When
        $tester = self::console(ClientTokenListCommand::NAME);

        // Then
        static::assertStringContainsString('revoked on', self::flattened($tester));
    }

    #[Test]
    public function anIdentifierNoTokenCarriesIsSaidToBeNoneOfTheTenants(): void
    {
        // When
        $tester = self::console(ClientTokenRevokeCommand::NAME, [
            'id' => Uuid::v7()->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('has no initial access token', self::flattened($tester));
    }

    #[Test]
    public function aValueThatIsNoIdentifierIsRefusedBeforeAnythingIsRead(): void
    {
        // Given
        $this->issue();

        // When
        $tester = self::console(ClientTokenRevokeCommand::NAME, [
            'id' => 'not-an-identifier',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertCount(1, [...self::service('test.beffroi.initial_access_tokens', IssuedInitialAccessTokensInterface::class)->issuedIn(self::tenant())]);
    }

    #[Test]
    public function aTokenWorthNoRegistrationIsNotIssued(): void
    {
        // When
        $tester = $this->issue(registrations: 0);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('worth at least one registration', self::flattened($tester));
    }

    #[Test]
    public function aTokenWorthNothingForADayIsNotIssued(): void
    {
        // When
        $tester = $this->issue(days: 0);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('worth something for a day at least', self::flattened($tester));
    }

    private function issue(int $registrations = 1, int $days = 30): CommandTester
    {
        return self::console(ClientTokenIssueCommand::NAME, [
            'name' => self::NAME,
            '--registrations' => (string) $registrations,
            '--days' => (string) $days,
        ]);
    }

    private function register(string $token): void
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => 'client_secret_basic',
            ], JSON_THROW_ON_ERROR),
        );
    }
}
