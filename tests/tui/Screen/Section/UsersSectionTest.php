<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use function array_filter;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;
use function str_starts_with;

/**
 * A user is read when the administrator asks for one, and their sessions and their journal when the administrator asks
 * for them: each read is an act of their journal (decisions 0022 and 0038), which the screen says first.
 */
final class UsersSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function nothingIsReadOfAPersonUntilTheAdministratorAsks(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        $this->screen->open('section.users');

        // Then
        static::assertSame(
            [[], true],
            [
                array_filter($this->screen->http->requests, static fn (array $request): bool => str_starts_with(
                    $request['url'],
                    FakeProvider::ADMINISTRATION . '/users',
                )),
                str_contains($this->screen->screen(), 'Reading a person, their sessions or their journal'),
            ],
        );
    }

    #[Test]
    public function aUsernameTypedThenEnterReadsTheUser(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true, 1], [
            str_contains($screen, 'Alice Liddell'),
            str_contains($screen, 'administrators (local)'),
            preg_match('/passkey +YubiKey/', $screen),
        ]);
    }

    #[Test]
    public function aUsernameThatNamesNobodyIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen([]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('nobody');

        // When
        $this->screen->press("\r");

        // Then
        static::assertStringContainsString('Nobody of the tenant has the username nobody.', $this->screen->screen());
    }

    /**
     * Once a person is shown, the keys go to what can be read of them, and `s` reads their open sessions.
     */
    #[Test]
    public function theSessionsAreReadWhenTheAdministratorAsksForThem(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => [
                'sessions' => [[
                    'id' => 'session-1',
                    'authenticated_at' => '2026-11-04T09:00:00Z',
                    'last_seen_at' => '2026-11-04T09:30:00Z',
                    'expires_at' => '2026-11-04T17:00:00Z',
                    'acr' => 'phr',
                    'methods' => ['hwk', 'user'],
                    'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => 'Lille, France'],
                ]],
            ],
        ]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('s');

        // Then
        static::assertSame(
            [1, 0, true],
            [
                $this->screen->requestsTo('/users/0193-alice/sessions'),
                $this->screen->requestsTo('/users/0193-alice/journal'),
                str_contains($this->screen->screen(), '203.0.113.4'),
            ],
        );
    }

    #[Test]
    public function theJournalIsReadWhenTheAdministratorAsksForIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/journal' => [
                'acts' => [[
                    'id' => 'act-1',
                    'act' => 'user.authenticated',
                    'occurred_at' => '2026-11-04T09:00:00Z',
                    'client' => 'oidc-demo',
                    'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => null],
                ]],
            ],
        ]);
        $this->screen->open('section.users');
        $this->screen->press("\t");
        $this->screen->type('alice');
        $this->screen->press("\r");

        // When
        $this->screen->press('j');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([0, 1], [
            $this->screen->requestsTo('/users/0193-alice/sessions'),
            preg_match('/2026-11-04 09:00 +sign-ins +oidc-demo/', $screen),
        ]);
    }

    /**
     * The key that changes a row is on the last line of the screen while its table has the focus.
     */
    #[Test]
    public function theKeyThatRevokesACredentialIsSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/users?username=alice' => self::alice()]);

        // When
        self::lookUpAlice($this->screen);

        // Then
        static::assertStringContainsString('x  revoke', $this->screen->screen());
    }

    /**
     * Decision 0038: a change of a person is asked to be confirmed, and nothing is sent before it is.
     */
    #[Test]
    public function aChangeIsAskedToBeConfirmedBeforeItIsMade(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('s');

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($this->screen->screen(), 'End the session of alice authenticated 2026-11-04 09:00'),
        ]);
    }

    #[Test]
    public function anOpenSessionIsEndedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
            'DELETE /users/0193-alice/sessions/session-1' => ['id' => 'session-1', 'ended_at' => '2026-11-04T10:00:00Z'],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['s', 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, false, true], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($screen, '203.0.113.4'),
            str_contains($screen, 'The session of alice is ended'),
        ]);
    }

    /**
     * A change the administrator did not confirm at once is forgotten, and a `y` pressed later confirms nothing.
     */
    #[Test]
    public function anyOtherKeyThanYForgetsTheChange(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            '/users/0193-alice/sessions' => self::sessionsOfAlice(),
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press(['s', 'x']);

        // When
        $this->screen->press(['n', 'y']);

        // Then
        static::assertSame([0, false], [
            $this->screen->requestsTo('/users/0193-alice/sessions/session-1', 'DELETE'),
            str_contains($this->screen->screen(), 'End the session of alice'),
        ]);
    }

    #[Test]
    public function aCredentialIsRevokedOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/users?username=alice' => self::alice(),
            'DELETE /users/0193-alice/credentials/credential-1' => [
                'id' => 'credential-1',
                'kind' => 'passkey',
                'name' => 'YubiKey',
                'revoked_at' => '2026-11-04T10:00:00Z',
            ],
        ]);
        self::lookUpAlice($this->screen);
        $this->screen->press('x');

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, true], [
            $this->screen->requestsTo('/users/0193-alice/credentials/credential-1', 'DELETE'),
            str_contains($screen, '2026-11-04 10:00'),
            str_contains($screen, 'The passkey credential YubiKey of alice is revoked'),
        ]);
    }

    /**
     * A password is replaced, never revoked: the screen says so and asks nothing.
     */
    #[Test]
    public function aCredentialNoRevocationAppliesToIsNotOffered(): void
    {
        // Given
        $alice = self::alice();
        $alice['credentials'] = [[
            'id' => 'credential-2',
            'kind' => 'password',
            'revocable' => false,
            'created_at' => '2026-10-01T08:00:00Z',
        ]];
        $this->screen = new SignedInScreen(['/users?username=alice' => $alice]);
        self::lookUpAlice($this->screen);

        // When
        $this->screen->press(['x', 'y']);

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/users/0193-alice/credentials/credential-2', 'DELETE'),
            str_contains($this->screen->screen(), 'A password is replaced, never revoked'),
        ]);
    }

    /**
     * The letters the screen answers to are the field's while the administrator types in it.
     */
    #[Test]
    public function theLettersTypedInTheFieldAreTheFieldsOwn(): void
    {
        // Given
        $this->screen = new SignedInScreen([]);
        $this->screen->open('section.users');
        $this->screen->press("\t");

        // When
        $this->screen->type('qr');

        // Then
        static::assertSame([true, true], [$this->screen->shell->typing($this->screen->tui), str_contains($this->screen->screen(), 'Username: qr')]);
    }

    private static function lookUpAlice(SignedInScreen $screen): void
    {
        $screen->open('section.users');
        $screen->press("\t");
        $screen->type('alice');
        $screen->press("\r");
    }

    /**
     * @return array<string, mixed>
     */
    private static function sessionsOfAlice(): array
    {
        return [
            'sessions' => [[
                'id' => 'session-1',
                'authenticated_at' => '2026-11-04T09:00:00Z',
                'last_seen_at' => '2026-11-04T09:30:00Z',
                'expires_at' => '2026-11-04T17:00:00Z',
                'acr' => 'phr',
                'methods' => ['hwk', 'user'],
                'provenance' => ['address' => '203.0.113.4', 'user_agent' => 'Firefox', 'place' => 'Lille, France'],
            ]],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function alice(): array
    {
        return [
            'id' => '0193-alice',
            'subject' => 'subject-of-alice',
            'username' => 'alice',
            'enabled' => true,
            'source' => 'local',
            'created_at' => '2026-10-01T08:00:00Z',
            'claims' => ['name' => 'Alice Liddell', 'email' => 'alice@example.com'],
            'groups' => [['name' => 'administrators', 'source' => 'local']],
            'credentials' => [[
                'id' => 'credential-1',
                'kind' => 'passkey',
                'name' => 'YubiKey',
                'authenticator' => 'YubiKey 5 NFC',
                'created_at' => '2026-10-01T08:00:00Z',
                'last_used_at' => '2026-11-04T09:00:00Z',
                'revocable' => true,
            ]],
        ];
    }
}
