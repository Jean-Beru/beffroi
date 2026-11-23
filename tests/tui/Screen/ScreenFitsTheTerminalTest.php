<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use function array_map;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;
use function str_contains;

/**
 * The screen is as tall and as wide as the terminal and never more, whatever the section and whatever it read: a
 * screen that drew more rows than the terminal has would push its first rows out of sight, the header first, so the
 * header stays on the first row and the keys on the last.
 */
final class ScreenFitsTheTerminalTest extends TestCase
{
    /**
     * The columns and the rows of each terminal the screen is drawn in.
     *
     * @var list<array{int, int}>
     */
    private const array TERMINALS = [[60, 16], [84, 24], [120, 30], [200, 60]];

    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    #[DataProvider('provideSectionsAndTerminals')]
    public function theHeaderStaysOnTheFirstRowAndTheKeysOnTheLast(string $section, int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), columns: $columns, rows: $rows);

        // When
        $this->screen->open($section);

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'choose')]);
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideSectionsAndTerminals(): iterable
    {
        foreach ([
            'section.instance',
            'section.session',
            'section.tenant',
            'section.clients',
            'section.keys',
            'section.mail_signing_keys',
            'section.users',
            'section.groups',
            'section.monitoring',
        ] as $section) {
            foreach (self::TERMINALS as [$columns, $rows]) {
                yield sprintf('%s on %d by %d', $section, $columns, $rows) => [$section, $columns, $rows];
            }
        }
    }

    /**
     * The form of an account holds more members than a small terminal has rows: the table shows those that fit.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theFormOfAnAccountKeepsTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(
            [
                '/users?username=alice' => [
                    'id' => '0193-alice',
                    'username' => 'alice',
                    'claims' => ['name' => 'Alice Pleasance Liddell, who went down the rabbit hole', 'address' => ['locality' => 'Oxford']],
                    'groups' => [],
                    'credentials' => [],
                ],
            ],
            columns: $columns,
            rows: $rows,
        );
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('e');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'save')]);
    }

    /**
     * The applications a person agreed to, more than a small terminal has rows, in the height the person leaves.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theApplicationsOfAPersonKeepTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(
            [
                '/users?username=alice' => [
                    'id' => '0193-alice',
                    'username' => 'alice',
                    'claims' => ['name' => 'Alice Pleasance Liddell'],
                    'groups' => [],
                    'credentials' => [],
                ],
                '/users/0193-alice/consents' => ['consents' => array_map(
                    static fn (int $number): array => [
                        'id' => sprintf('consent-%d', $number),
                        'client_id' => sprintf('a-client-with-a-long-identifier-%d', $number),
                        'client_name' => sprintf('The application number %d of the tenant', $number),
                        'scope' => 'openid profile email offline_access',
                        'claims' => [],
                        'granted_at' => '2026-10-21T10:00:00Z',
                        'renewable' => 2,
                        'last_renewed_at' => null,
                        'awaiting' => 0,
                    ],
                    range(1, 40),
                )],
            ],
            columns: $columns,
            rows: $rows,
        );
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('a');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'take back')]);
    }

    /**
     * The members of a group beside the groups, and the field that asks for one more, in the height the screen leaves.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theMembersOfAGroupAndItsFieldKeepTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), columns: $columns, rows: $rows);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", "\r"]);

        // When
        $this->screen->press('a');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'add')]);
    }

    /**
     * The initial access tokens of the tenant, more than a small terminal has rows, in place of the clients.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theInitialAccessTokensKeepTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), columns: $columns, rows: $rows);
        $this->screen->open('section.clients');
        $this->screen->press("\r");

        // When
        $this->screen->press('i');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'new token')]);
    }

    /**
     * The form of a new initial access token beside the tokens, in the height the screen leaves.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theFormOfATokenKeepsTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), columns: $columns, rows: $rows);
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i']);

        // When
        $this->screen->press('n');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'issue')]);
    }

    /**
     * The value of a token just issued, in place of its form, in the height the screen leaves.
     */
    #[Test]
    #[DataProvider('provideTerminals')]
    public function theValueOfATokenKeepsTheHeaderOnTheFirstRowAndTheKeysOnTheLast(int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(
            [
                ...self::answers(),
                'POST /initial-access-tokens' => SignedInScreen::answered([
                    'id' => 'token-new',
                    'name' => 'The terminal of an administrator who works from a second floor',
                    'expires_at' => '2026-12-17T08:00:00Z',
                    'registrations_allowed' => 1,
                    'registrations_served' => 0,
                    'administration' => true,
                    'revoked_at' => null,
                    'authorises_a_registration' => true,
                    'value' => 'a-value-as-long-as-the-one-an-instance-draws-for-a-token',
                ], 201),
            ],
            columns: $columns,
            rows: $rows,
        );
        $this->screen->open('section.clients');
        $this->screen->press(["\r", 'i', 'n']);

        // When
        $this->screen->press('s');

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'close')]);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideTerminals(): iterable
    {
        foreach (self::TERMINALS as [$columns, $rows]) {
            yield sprintf('%d by %d', $columns, $rows) => [$columns, $rows];
        }
    }

    /**
     * What an instance with some history answers: more clients, initial access tokens and groups than a screen holds, keys
     * in every state, a point of its health that does not hold, and acts of many names.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function answers(): array
    {
        return [
            '/tenant' => [
                'slug' => 'default',
                'issuer' => 'https://op.example',
                'name' => 'An instance whose name is longer than a narrow terminal is wide',
                'created_at' => '2026-10-01T08:00:00Z',
                'login_floor' => 'any_proof',
                'authentication_classes' => [['acr' => '1', 'predicate' => 'single_factor'], ['acr' => 'phr', 'predicate' => 'phishing_resistant']],
                'administrators' => ['administrators', 'operators', 'security officers'],
                'administration_api' => 'https://admin.op.example',
                'journal_retention_days' => 180,
            ],
            '/clients' => ['clients' => array_map(
                static fn (int $number): array => [
                    'client_id' => sprintf('client-%d-with-an-identifier-drawn-at-random', $number),
                    'client_name' => sprintf('Client number %d, registered by the conformance suite', $number),
                    'source' => 'registration',
                    'registered_at' => '2026-10-21T10:00:00Z',
                    'last_used_at' => null,
                ],
                range(1, 40),
            )],
            '/initial-access-tokens' => ['initial_access_tokens' => array_map(
                static fn (int $number): array => [
                    'id' => sprintf('token-%d', $number),
                    'name' => sprintf('Token number %d, for the integration of a partner with a long name', $number),
                    'expires_at' => '2026-12-17T08:00:00Z',
                    'registrations_allowed' => 5,
                    'registrations_served' => $number % 6,
                    'administration' => $number === 1,
                    'revoked_at' => ($number % 7) === 0 ? '2026-11-10T08:00:00Z' : null,
                    'authorises_a_registration' => ($number % 6) !== 5 && ($number % 7) !== 0,
                ],
                range(1, 40),
            )],
            '/tenant/mail-signing-keys' => ['keys' => array_map(static fn (bool $current): array => [
                'format' => $current ? 'smime' : 'pgp',
                'fingerprint' => '9B8A7C6D5E4F30211203F4E5D6C7B8A99B8A7C6D5E4F30211203F4E5D6C7B8A9',
                'current' => $current,
                'senders' => ['security-notifications@a-tenant-with-a-long-name.example'],
                'published' => '',
                'set_at' => '2026-11-01T08:00:00Z',
                'not_after' => $current ? '2027-11-01T08:00:00Z' : null,
                'replaced_at' => $current ? null : '2026-11-20T08:00:00Z',
            ], [true, false])],
            '/keys' => ['keys' => array_map(static fn (string $status): array => [
                'kid' => sprintf('k-2026-11-01-ES256-%s', $status),
                'algorithm' => 'ES256',
                'use' => 'sig',
                'status' => $status,
                'created_at' => '2026-11-01T00:00:00Z',
                'activation_due_at' => '2026-11-01T00:02:00Z',
                'activated_at' => '2026-11-01T00:02:00Z',
                'retiring_at' => null,
                'retirement_due_at' => null,
                'retired_at' => null,
                'past_its_age' => false,
            ], ['active', 'staged', 'retiring', 'retired'])],
            '/groups' => ['groups' => array_map(
                static fn (int $number): array => [
                    'id' => sprintf('group-%d', $number),
                    'name' => sprintf('Group number %d, whose name a directory wrote at length', $number),
                    'source' => 'scim',
                    'members' => $number * 3,
                    'administers' => $number === 1,
                    'created_at' => '2026-10-21T10:00:00Z',
                ],
                range(1, 30),
            )],
            '/groups/group-1/members' => ['members' => array_map(
                static fn (int $number): array => [
                    'person' => ['id' => sprintf('person-%d', $number), 'username' => sprintf('member.number.%d@a-long-domain.example', $number)],
                    'source' => 'local',
                    'added_at' => '2026-10-21T10:00:00Z',
                ],
                range(1, 40),
            )],
            '/health' => [
                'checks' => [
                    [
                        'about' => 'The lane of the notifications tries a logout token again on the schedule the window assumes',
                        'green' => true,
                        'lines' => ['It tries six times over two hours.'],
                    ],
                    [
                        'about' => 'The KMS opens the active signing key',
                        'green' => false,
                        'lines' => ['Connection refused.', 'Nothing is signed until it opens.', 'Start the KMS, then look again.'],
                    ],
                ],
            ],
            '/statistics' => [
                'since' => '2026-05-08T10:00:00Z',
                'until' => '2026-11-04T10:00:00Z',
                'users' => 1200,
                'clients' => 40,
                'open_sessions' => 310,
                'keys' => ['staged' => 1, 'active' => 1, 'retiring' => 1, 'retired' => 1],
                'acts' => array_map(static fn (int $number): array => ['act' => sprintf('act.number_%d', $number), 'count' => $number * 17], range(1, 20)),
                'queues' => [['transport' => 'async', 'messages' => 4]],
            ],
        ];
    }
}
