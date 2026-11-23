<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use function count;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function sprintf;
use function str_contains;

/**
 * The clients of the tenant, listed by their name, what one of them registered once the administrator asks, and a client
 * deleted; the initial access tokens of the tenant, a token issued from a form and its value shown once, and a token
 * revoked, each change an act of the tenant that names the administrator (decision 0038).
 */
final class ClientsSectionTest extends TestCase
{
    private const string VALUE = 'the-value-of-the-token-issued';

    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function theClientsAreListedByTheirNameWithWhereTheyCameFrom(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [
                self::client('oidc-demo', 'The demonstration', 'configuration', '2026-11-04T10:00:00Z'),
                self::client('TS5oFb4MAr11', null, 'registration', null),
            ]],
        ]);

        // When
        $this->screen->open('section.clients');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1], [
            preg_match('/The demonstration +oidc-demo +configuration .*2026-11-04 10:00/', $screen),
            preg_match('/- +TS5oFb4MAr11 +registration /', $screen),
        ]);
    }

    /**
     * Enter goes into the list, and Enter on a client reads what it registered, its identifier written as a segment
     * of the path (RFC 3986 §3.3).
     */
    #[Test]
    public function enterOnAClientReadsWhatItRegistered(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('a client', 'A client', 'registration', null)]],
            '/clients/a%20client' => [
                ...self::client('a client', 'A client', 'registration', null),
                'administration' => true,
                'metadata' => [
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'redirect_uris' => ['http://127.0.0.1:8123/callback'],
                ],
            ],
        ]);
        $this->screen->open('section.clients');

        // When
        $this->screen->press(["\r", "\r"]);

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true, true], [
            str_contains($screen, 'Registered metadata'),
            str_contains($screen, 'private_key_jwt'),
            str_contains($screen, 'http://127.0.0.1:8123/callback'),
        ]);
    }

    /**
     * Decision 0009: a name a third party registered is shown, and the terminal is handed none of it as a sequence.
     */
    #[Test]
    public function aNameAThirdPartyRegisteredIsDrawnAsText(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => [self::client('evil', "Evil\e]0;owned\x07", 'registration', null)]]]);

        // When
        $this->screen->open('section.clients');

        // Then
        static::assertSame(
            [false, true],
            [str_contains($this->screen->terminal->getOutput(), "\e]0;owned"), str_contains($this->screen->screen(), 'Evil]0;owned')],
        );
    }

    #[Test]
    public function aTenantWithoutAClientIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => []]]);

        // When
        $this->screen->open('section.clients');

        // Then
        static::assertStringContainsString('No client.', $this->screen->screen());
    }

    /**
     * RFC 7591 §1.2: a client registered by an initial access token shows what the token gave it beside what it
     * registered.
     */
    #[Test]
    public function anOpenedClientShowsWhatItsInitialAccessTokenGaveIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('invoices', 'Invoices', 'registration', null)]],
            '/clients/invoices' => [
                ...self::client('invoices', 'Invoices', 'registration', null),
                'granted' => ['resources' => ['https://api.example/invoices']],
            ],
        ]);
        $this->screen->open('section.clients');

        // When
        $this->screen->press(["\r", "\r"]);

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true], [
            str_contains($screen, 'Granted by its initial access token'),
            str_contains($screen, 'https://api.example/invoices'),
        ]);
    }

    /**
     * A client deleted can spend nothing it was issued any more, so it is asked first.
     */
    #[Test]
    public function deletingAClientIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => [self::client('invoices', 'Invoices', 'registration', null)]]]);
        $this->screen->open('section.clients');
        $this->screen->press("\r");

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/clients/invoices', 'DELETE'),
            str_contains($this->screen->screen(), 'Delete the client invoices?'),
        ]);
    }

    #[Test]
    public function aClientIsDeletedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('invoices', 'Invoices', 'registration', null)]],
            'DELETE /clients/invoices' => ['client_id' => 'invoices', 'deleted_at' => '2026-11-17T10:00:00Z'],
        ]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 0, true], [
            $this->screen->requestsTo('/clients/invoices', 'DELETE'),
            preg_match('/Invoices +invoices/', $screen),
            str_contains($screen, 'Client invoices deleted'),
        ]);
    }

    #[Test]
    public function anyOtherKeyThanYDeletesNoClient(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => [self::client('invoices', 'Invoices', 'registration', null)]]]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'x']);

        // When
        $this->screen->press(['n', 'y']);

        // Then
        static::assertSame([0, false], [
            $this->screen->requestsTo('/clients/invoices', 'DELETE'),
            str_contains($this->screen->screen(), 'Delete the client invoices?'),
        ]);
    }

    /**
     * Decision 0038: a client the deployment declares is not deleted, and the instance says why.
     */
    #[Test]
    public function aClientTheInstanceDoesNotDeleteIsSaidInItsWords(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('oidc-demo', 'The demonstration', 'configuration', null)]],
            'DELETE /clients/oidc-demo' => SignedInScreen::answered([
                'error' => 'conflict',
                'error_description' => 'The client "oidc-demo" is declared in the configuration of the deployment, which alone takes it back.',
            ], 409),
        ]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'x']);

        // When
        $this->screen->press('y');

        // Then
        static::assertSame([true, 1], [
            str_contains($this->screen->screen(), 'Nothing was changed: The client "oidc-demo" is declared in the configuration'),
            preg_match('/The demonstration +oidc-demo/', $this->screen->screen()),
        ]);
    }

    #[Test]
    public function theInitialAccessTokensAreReadOnlyWhenAsked(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => [self::token()]],
        ]);
        $this->screen->open('section.clients');

        // When
        $this->screen->press("\r");

        // Then
        static::assertSame(0, $this->screen->requestsTo('/initial-access-tokens'));
    }

    /**
     * @param array<string, mixed> $token
     */
    #[Test]
    #[DataProvider('provideTokensAndWhatTheyStillDo')]
    public function iListsTheInitialAccessTokensWithWhatEachStillDoes(array $token, string $state): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => [$token]],
        ]);
        $this->screen->open('section.clients');
        $this->screen->press("\r");

        // When
        $this->screen->press('i');

        // Then
        static::assertMatchesRegularExpression(sprintf('/laptop +%s /', $state), $this->screen->screen());
    }

    #[Test]
    public function aTokenIsListedWithTheRegistrationsItServedItsExpiryAndWhetherItsClientsAdminister(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => [self::token()]],
        ]);
        $this->screen->open('section.clients');
        $this->screen->press("\r");

        // When
        $this->screen->press('i');

        // Then
        static::assertMatchesRegularExpression('/laptop +authorises a registration +0 of 1 +2026-12-17 08:00 +yes/', $this->screen->screen());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideTokensAndWhatTheyStillDo(): iterable
    {
        yield 'one that authorises a registration' => [self::token(), 'authorises a registration'];
        yield 'one revoked' => [self::token(revokedAt: '2026-11-17T09:00:00Z'), 'revoked on 2026-11-17 09:00'];
        yield 'one that served every registration it allows' => [self::token(served: 1), 'spent'];
        yield 'one past its expiry' => [self::token(authorises: false), 'expired'];
    }

    #[Test]
    public function theKeysOfTheInitialAccessTokensAreSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => []], '/initial-access-tokens' => ['initial_access_tokens' => []]]);
        $this->screen->open('section.clients');
        $this->screen->press("\r");

        // When
        $this->screen->press('i');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertMatchesRegularExpression('/ n +new token +x +revoke +c +clients /', $lines[count($lines) - 1]);
    }

    #[Test]
    public function aTokenIsIssuedFromTheForm(): void
    {
        // Given
        $this->screen = self::aFormFilled();

        // When
        $this->screen->press('s');

        // Then
        static::assertSame(
            ['{"name":"laptop","registrations":1,"days":30,"administration":true}'],
            $this->screen->bodiesTo('/initial-access-tokens', 'POST'),
        );
    }

    /**
     * RFC 7591 §1.2: nothing can show the value of a token again, so it is shown once its token is issued.
     */
    #[Test]
    public function theValueOfATokenIssuedIsShownOnce(): void
    {
        // Given
        $this->screen = self::aFormFilled();

        // When
        $this->screen->press('s');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true], [
            str_contains($screen, self::VALUE),
            str_contains($screen, 'it will not be shown again'),
        ]);
    }

    #[Test]
    public function theValueOfATokenLeavesTheScreenOnceClosed(): void
    {
        // Given
        $this->screen = self::aFormFilled();
        $this->screen->press('s');

        // When
        $this->screen->press("\r");

        // Then
        static::assertStringNotContainsString(self::VALUE, $this->screen->screen());
    }

    #[Test]
    public function closingTheValueGivesTheTokensBackWithTheOneIssued(): void
    {
        // Given
        $this->screen = self::aFormFilled();
        $this->screen->press('s');

        // When
        $this->screen->press("\r");

        // Then
        static::assertMatchesRegularExpression('/laptop +authorises a registration +0 of 1/', $this->screen->screen());
    }

    #[Test]
    public function aTokenTheInstanceRefusesToIssueIsSaidInItsWords(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => []],
            'POST /initial-access-tokens' => SignedInScreen::answered([
                'error' => 'invalid_request',
                'error_description' => 'An initial access token is worth something for a day at least.',
            ], 400),
        ]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i', 'n']);

        // When
        $this->screen->press('s');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true], [
            str_contains($screen, 'Nothing was changed: An initial access token is worth something for a day at least.'),
            str_contains($screen, 'New initial access token'),
        ]);
    }

    /**
     * The clients a token registered stay, and the question says it.
     */
    #[Test]
    public function revokingATokenIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => []], '/initial-access-tokens' => ['initial_access_tokens' => [self::token()]]]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i']);

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/initial-access-tokens/t-laptop', 'DELETE'),
            str_contains($this->screen->screen(), 'Revoke the initial access token laptop?'),
        ]);
    }

    #[Test]
    public function aTokenIsRevokedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => [self::token()]],
            'DELETE /initial-access-tokens/t-laptop' => self::token(revokedAt: '2026-11-17T09:00:00Z'),
        ]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i', 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1, true], [
            $this->screen->requestsTo('/initial-access-tokens/t-laptop', 'DELETE'),
            preg_match('/laptop +revoked on 2026-11-17 09:00/', $screen),
            str_contains($screen, 'Initial access token laptop revoked'),
        ]);
    }

    #[Test]
    public function cShowsTheClientsAgain(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('invoices', 'Invoices', 'registration', null)]],
            '/initial-access-tokens' => ['initial_access_tokens' => [self::token()]],
        ]);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i']);

        // When
        $this->screen->press('c');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 0], [preg_match('/Invoices +invoices/', $screen), preg_match('/laptop +authorises/', $screen)]);
    }

    /**
     * The form of a new token, its name typed and the administration turned over, before it is issued.
     */
    private static function aFormFilled(): SignedInScreen
    {
        $screen = new SignedInScreen([
            '/clients' => ['clients' => []],
            '/initial-access-tokens' => ['initial_access_tokens' => []],
            'POST /initial-access-tokens' => SignedInScreen::answered([...self::token(), 'value' => self::VALUE], 201),
        ]);
        $screen->open('section.clients');
        $screen->press(["\r", 'i', 'n', "\r"]);
        $screen->type('laptop');
        $screen->press(["\r", "\e[B", "\e[B", "\e[B", "\r"]);

        return $screen;
    }

    /**
     * An initial access token of one registration, for the clients of the administration.
     *
     * @return array<string, mixed>
     */
    private static function token(?string $revokedAt = null, int $served = 0, bool $authorises = true): array
    {
        return [
            'id' => 't-laptop',
            'name' => 'laptop',
            'issued_at' => '2026-11-17T08:00:00Z',
            'expires_at' => '2026-12-17T08:00:00Z',
            'registrations_allowed' => 1,
            'registrations_served' => $served,
            'administration' => true,
            'granted' => null,
            'revoked_at' => $revokedAt,
            'authorises_a_registration' => $authorises && $revokedAt === null && $served === 0,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function client(string $clientId, ?string $name, string $source, ?string $lastUsedAt): array
    {
        return [
            'client_id' => $clientId,
            'client_name' => $name,
            'source' => $source,
            'registered_at' => null,
            'last_used_at' => $lastUsedAt,
        ];
    }
}
