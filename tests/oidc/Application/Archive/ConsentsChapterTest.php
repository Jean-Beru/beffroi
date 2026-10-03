<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Archive;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Archive\ConsentsChapter;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use function array_column;
use function array_map;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: what a person has agreed to, in the archive they ask for. It is a chapter of this module and
 * not of the core, which is the reason a chapter is a port at all: the core knows no protocol, and a
 * consent is what OAuth calls the permission a person gave a client.
 */
final class ConsentsChapterTest extends TestCase
{
    #[Test]
    public function aConsentIsOnTheClientItWasGivenToAndWhatItGranted(): void
    {
        // Given
        $user = Fixtures::user();
        $client = self::client($user);
        $consents = new InMemoryConsentRepository();
        $consents->save(self::consent($user, $client, ['openid', 'profile']));

        // When
        $lines = new ConsentsChapter($consents)->of($user);

        // Then
        static::assertSame(
            [
                [
                    'client_id' => $client->registration->clientId,
                    'client_name' => $client->registration->presentation->name,
                    'scopes' => ['openid', 'profile'],
                    'authorization_details' => null,
                    'granted_at' => Fixtures::now()->format('c'),
                ],
            ],
            $lines,
        );
    }

    /**
     * What is in force and not what ever was: a consent taken back is not a permission a client holds, and
     * the page of the account reads the same answer.
     */
    #[Test]
    public function aConsentThatWasTakenBackIsNotInTheChapter(): void
    {
        // Given
        $user = Fixtures::user();
        $consents = new InMemoryConsentRepository();
        $consent = self::consent($user, self::client($user), ['openid']);
        $consent->revoke(Fixtures::now());
        $consents->save($consent);

        // When / Then
        static::assertSame([], new ConsentsChapter($consents)->of($user));
    }

    /**
     * One line per client, the most recently granted first, as the page of the account reads them.
     */
    #[Test]
    public function aPersonWhoAgreedToTwoClientsHasTwoLines(): void
    {
        // Given
        $user = Fixtures::user();
        $consents = new InMemoryConsentRepository();
        $consents->save(self::consent($user, self::client($user, 'oidc-demo'), ['openid']));
        $consents->save(self::consent($user, self::client($user, 'native-app'), ['openid'], Fixtures::now()->modify('+1 hour')));

        // When
        $lines = new ConsentsChapter($consents)->of($user);

        // Then
        static::assertCount(2, $lines);
        static::assertSame(['native-app', 'oidc-demo'], array_column($lines, 'client_id'));
    }

    #[Test]
    public function aPersonWhoAgreedToNothingHasAnEmptyChapter(): void
    {
        // When / Then
        static::assertSame([], new ConsentsChapter(new InMemoryConsentRepository())->of(Fixtures::user()));
    }

    private static function client(User $user, string $clientId = 'oidc-demo'): Client
    {
        return Clients::confidential($user->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: $clientId);
    }

    /**
     * @param list<string> $scopes
     */
    private static function consent(User $user, Client $client, array $scopes, ?DateTimeImmutable $grantedAt = null): Consent
    {
        return new Consent(
            Uuid::v7(),
            $user,
            $client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $grantedAt ?? Fixtures::now(),
        );
    }
}
