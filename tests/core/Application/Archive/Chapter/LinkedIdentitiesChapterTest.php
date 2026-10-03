<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\LinkedIdentitiesChapter;
use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_column;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the identities a person has at upstream providers, in the archive they ask for. The claims
 * are in the file because they are what this provider holds of that person, received from somewhere else:
 * an answer that left out what a federation sent would be an answer about our own forms.
 */
final class LinkedIdentitiesChapterTest extends TestCase
{
    private const array CLAIMS = [
        'email' => 'ada@example.org',
        'name' => 'Augusta Ada King-Noel',
    ];

    #[Test]
    public function anIdentityIsOnItsProviderItsSubjectAndItsClaims(): void
    {
        // Given
        $user = Fixtures::user();
        $identities = new InMemoryLinkedIdentityRepository();
        $identities->save(self::identity($user, 'login.acme-federation.example'));

        // When
        $lines = new LinkedIdentitiesChapter($identities)->of($user);

        // Then
        static::assertSame(
            [
                [
                    'provider' => 'login.acme-federation.example',
                    'sub' => '110169484474386276334',
                    'claims' => self::CLAIMS,
                    'linked_at' => Fixtures::now()->format('c'),
                    'last_seen_at' => Fixtures::now()->format('c'),
                ],
            ],
            $lines,
        );
    }

    /**
     * The most recently linked first, which is the order the port answers in.
     */
    #[Test]
    public function theIdentitiesAreMostRecentlyLinkedFirst(): void
    {
        // Given
        $user = Fixtures::user();
        $identities = new InMemoryLinkedIdentityRepository();
        $identities->save(self::identity($user, 'login.first.example'));
        $identities->save(self::identity($user, 'login.second.example', Fixtures::now()->modify('+1 day')));

        // When
        $lines = new LinkedIdentitiesChapter($identities)->of($user);

        // Then
        static::assertSame(['login.second.example', 'login.first.example'], array_column($lines, 'provider'));
    }

    #[Test]
    public function theIdentitiesOfAnotherPersonAreNotInTheChapter(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $ada = Fixtures::user($tenant, 'ada', 'ada-subject');
        $grace = Fixtures::user($tenant, 'grace', 'grace-subject');
        $identities = new InMemoryLinkedIdentityRepository();
        $identities->save(self::identity($grace, 'login.acme-federation.example'));

        // When / Then
        static::assertSame([], new LinkedIdentitiesChapter($identities)->of($ada));
    }

    #[Test]
    public function aPersonWithNoUpstreamIdentityHasAnEmptyChapter(): void
    {
        // When / Then
        static::assertSame([], new LinkedIdentitiesChapter(new InMemoryLinkedIdentityRepository())->of(Fixtures::user()));
    }

    private static function identity(User $user, string $provider, ?DateTimeImmutable $linkedAt = null): LinkedIdentity
    {
        $at = $linkedAt ?? Fixtures::now();

        return new LinkedIdentity(Uuid::v7(), $user, $provider, '110169484474386276334', self::CLAIMS, $at, $at);
    }
}
