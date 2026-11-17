<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use Closure;
use function count;
use function explode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Decision 0038: the groups of the tenant, their members read only when the administrator asks, a group created and a
 * membership given or taken back, each change an act that names the administrator.
 */
final class GroupsSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function theGroupsAreListedWithHowManyMembersEachHoldsAndWhetherTheyAdminister(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/groups' => self::tenantGroups()]);

        // When
        $this->screen->open('section.groups');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1], [
            preg_match('/administrators +local +1 +yes /', $screen),
            preg_match('/auditors +scim +0 +no /', $screen),
        ]);
    }

    /**
     * Decision 0022: reading a member is an act of theirs, so nothing is read before the administrator asks.
     */
    #[Test]
    public function nothingIsReadOfTheMembersUntilTheAdministratorAsks(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/groups' => self::tenantGroups()]);

        // When
        $this->screen->open('section.groups');
        $this->screen->press("\r");

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/groups/g-administrators/members'),
            str_contains($this->screen->screen(), 'Reading a member is an act written in their journal'),
        ]);
    }

    #[Test]
    public function enterOnAGroupReadsItsMembers(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            '/groups/g-administrators/members' => self::members(),
        ]);
        $this->screen->open('section.groups');

        // When
        $this->screen->press(["\r", "\r"]);

        // Then
        static::assertSame([1, 1], [
            $this->screen->requestsTo('/groups/g-administrators/members'),
            preg_match('/alice +local +2026-10-01/', $this->screen->screen()),
        ]);
    }

    #[Test]
    public function aGroupIsCreatedFromTheNameTyped(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            'POST /groups' => self::answered([
                'id' => 'g-staff',
                'name' => 'staff',
                'source' => 'local',
                'members' => 0,
                'administers' => false,
                'created_at' => '2026-11-17T10:00:00Z',
            ], 201),
        ]);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", 'n']);
        $this->screen->type('staff');

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([['{"name":"staff"}'], true, 1], [
            $this->screen->bodiesTo('/groups', 'POST'),
            str_contains($screen, 'The group staff is created.'),
            preg_match('/staff +local +0 +no /', $screen),
        ]);
    }

    #[Test]
    public function aMemberIsAddedToTheGroupChosenAndItsCountFollows(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            'POST /groups/g-administrators/members' => self::answered([
                'person' => ['id' => 'p-carol', 'username' => 'carol'],
                'source' => 'local',
                'added_at' => '2026-11-17T10:00:00Z',
            ], 201),
        ]);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", 'a']);
        $this->screen->type('carol');

        // When
        $this->screen->press("\r");

        // Then
        $screen = $this->screen->screen();
        static::assertSame([['{"username":"carol"}'], true, 1], [
            $this->screen->bodiesTo('/groups/g-administrators/members', 'POST'),
            str_contains($screen, 'carol is a member of administrators.'),
            preg_match('/administrators +local +2 +yes /', $screen),
        ]);
    }

    /**
     * Out of the last group that administers the tenant a person no longer administers it, so it is asked first.
     */
    #[Test]
    public function takingAMemberOutIsAskedToBeConfirmedFirst(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            '/groups/g-administrators/members' => self::members(),
        ]);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", "\r"]);

        // When
        $this->screen->press('x');

        // Then
        static::assertSame([0, true], [
            $this->screen->requestsTo('/groups/g-administrators/members/p-alice', 'DELETE'),
            str_contains($this->screen->screen(), 'last group that administers the tenant'),
        ]);
    }

    #[Test]
    public function aMemberIsTakenOutOnceTheAdministratorConfirmsIt(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            '/groups/g-administrators/members' => self::members(),
            'DELETE /groups/g-administrators/members/p-alice' => ['group' => 'g-administrators', 'person' => 'p-alice'],
        ]);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", "\r", 'x']);

        // When
        $this->screen->press('y');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, true, 1], [
            $this->screen->requestsTo('/groups/g-administrators/members/p-alice', 'DELETE'),
            str_contains($screen, 'alice is no longer a member of administrators.'),
            preg_match('/administrators +local +0 +yes /', $screen),
        ]);
    }

    #[Test]
    public function aRefusalIsSaidInTheWordsOfTheInstance(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/groups' => self::tenantGroups(),
            'POST /groups' => self::answered(['error' => 'conflict', 'error_description' => 'A group named "auditors" already exists in this tenant.'], 409),
        ]);
        $this->screen->open('section.groups');
        $this->screen->press(["\r", 'n']);
        $this->screen->type('auditors');

        // When
        $this->screen->press("\r");

        // Then
        static::assertStringContainsString('Nothing was changed: A group named "auditors" already exists in this tenant.', $this->screen->screen());
    }

    #[Test]
    public function theKeysOfTheGroupsAreSaid(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/groups' => self::tenantGroups()]);
        $this->screen->open('section.groups');

        // When
        $this->screen->press("\r");

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [
            str_contains($lines[count($lines) - 1], 'new group'),
            str_contains($lines[count($lines) - 1], 'add a member'),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function tenantGroups(): array
    {
        return [
            'groups' => [
                [
                    'id' => 'g-administrators',
                    'name' => 'administrators',
                    'source' => 'local',
                    'members' => 1,
                    'administers' => true,
                    'created_at' => '2026-10-01T08:00:00Z',
                ],
                [
                    'id' => 'g-auditors',
                    'name' => 'auditors',
                    'source' => 'scim',
                    'members' => 0,
                    'administers' => false,
                    'created_at' => '2026-10-02T08:00:00Z',
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function members(): array
    {
        return [
            'members' => [
                ['person' => ['id' => 'p-alice', 'username' => 'alice'], 'source' => 'local', 'added_at' => '2026-10-01T08:00:00Z'],
            ],
        ];
    }

    /**
     * @param array<string, mixed> $document
     *
     * @return Closure(): MockResponse
     */
    private static function answered(array $document, int $status): Closure
    {
        return static fn (): MockResponse => new MockResponse(json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), ['http_code' => $status]);
    }
}
