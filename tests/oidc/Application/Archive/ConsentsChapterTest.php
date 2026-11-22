<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Archive;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Archive\ConsentsChapter;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
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
                    'claims' => [],
                    'granted_at' => Fixtures::now()->format('c'),
                ],
            ],
            $lines,
        );
    }

    /**
     * OIDC Core §5.5
     */
    #[Test]
    public function aConsentSaysTheClaimsItWasGivenByName(): void
    {
        // Given
        $user = Fixtures::user();
        $consents = new InMemoryConsentRepository();
        $consents->save(self::consent($user, self::client($user), ['openid'], claims: new ClaimNames(['email', 'phone_number'])));

        // When
        $lines = new ConsentsChapter($consents)->of($user);

        // Then
        static::assertSame([['email', 'phone_number']], array_column($lines, 'claims'));
    }

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
    private static function consent(
        User $user,
        Client $client,
        array $scopes,
        ?DateTimeImmutable $grantedAt = null,
        ClaimNames $claims = new ClaimNames(),
    ): Consent {
        return new Consent(
            Uuid::v7(),
            $user,
            $client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            $grantedAt ?? Fixtures::now(),
            null,
            $claims,
        );
    }
}
