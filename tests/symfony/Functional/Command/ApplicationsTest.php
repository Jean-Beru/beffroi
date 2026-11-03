<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use function array_map;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use function preg_match;
use function preg_split;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use function trim;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #451, architecture §4.3, §5.5: the console says what every application holds of a person, for an
 * administrator asked what one of them is worth. It reads what the page of the account reads
 * (ApplicationHoldings), and a command that reads is not the command that writes: taking one back is
 * "beffroi:user:revoke-consent", which the client identifier of these rows is the argument of.
 */
final class ApplicationsTest extends ConsoleTestCase
{
    #[Test]
    public function theApplicationsTheUserAgreedToAreListedWithWhatTheyWereGranted(): void
    {
        // Given
        self::agree(self::user('alice'), ['openid', 'profile']);

        // When
        $tester = self::list('alice');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('oidc-demo', self::flattened($tester));
        static::assertStringContainsString('Demo application', self::flattened($tester));
        static::assertStringContainsString('openid profile', self::flattened($tester));
    }

    /**
     * OIDC Core §5.5: what the person agreed to by name is what the application holds beside its scopes, and
     * the row says it.
     */
    #[Test]
    public function theClaimsAgreedToByNameAreListedBesideTheScopes(): void
    {
        // Given
        self::agree(self::user('alice'), ['openid'], new ClaimNames(['email', 'phone_number']));

        // When
        $tester = self::list('alice');

        // Then
        static::assertStringContainsString('openid, by name: email phone_number', self::flattened($tester));
    }

    #[Test]
    public function whatTheApplicationCanStillRenewIsCounted(): void
    {
        // Given
        $alice = self::user('alice');
        self::agree($alice);
        self::refreshTokens()
            ->save(Tokens::refreshToken('the-refresh-token', self::client(), self::session($alice, self::currentSecond()), self::currentSecond()));

        // When
        $tester = self::list('alice');

        // Then
        static::assertSame('1', self::renewable($tester));
    }

    #[Test]
    public function aUserWhoAgreedToNothingIsSaidToHaveAgreedToNothing(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::list('alice');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('has agreed to let no application obtain anything', self::flattened($tester));
    }

    #[Test]
    public function aUserTheTenantDoesNotHaveIsRefused(): void
    {
        // When
        $tester = self::list('nobody');

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('nobody', self::flattened($tester));
    }

    /**
     * @param list<string> $scopes
     */
    private static function agree(User $user, array $scopes = ['openid'], ClaimNames $claims = new ClaimNames()): void
    {
        self::consents()
            ->save(new Consent(
                Uuid::v7(),
                $user,
                self::client(),
                new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
                self::currentSecond(),
                null,
                $claims,
            ));
    }

    private static function list(string $username): CommandTester
    {
        return self::console('beffroi:user:applications', [
            'username' => $username,
        ]);
    }

    /**
     * What the row of the only application of these tests says it can renew: its fifth cell, the cells of a
     * row of the console being what two spaces or more separate.
     */
    private static function renewable(CommandTester $tester): string
    {
        $display = $tester->getDisplay();
        static::assertSame(1, preg_match('/^\s+oidc-demo\s{2,}.*$/m', $display, $matches), $display);
        $cells = preg_split('/\s{2,}/', trim($matches[0]));
        static::assertIsArray($cells);

        return self::string($cells[4] ?? null);
    }

    private static function consents(): ConsentRepositoryInterface
    {
        return self::service('test.beffroi.consents', ConsentRepositoryInterface::class);
    }

    private static function refreshTokens(): RefreshTokenRepositoryInterface
    {
        return self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class);
    }
}
