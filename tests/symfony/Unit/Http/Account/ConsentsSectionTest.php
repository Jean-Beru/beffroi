<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Account;

use App\Http\Account\ConsentsSection;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * What the home of the account says of what a user has agreed to: how many clients may obtain something
 * about them.
 */
final class ConsentsSectionTest extends TestCase
{
    #[Test]
    public function anAccountThatAllowedNobodyIsSaidToHoldNone(): void
    {
        // Given
        $section = self::section();

        // When
        $state = $section->state(Fixtures::user());

        // Then
        static::assertSame('account.consents.state', $state->key);
        static::assertSame(
            [
                'count' => 0,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function theClientsTheAccountAllowedAreCounted(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section($user, ['oidc-demo', 'another-app']);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame(
            [
                'count' => 2,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function aConsentTakenBackIsCountedNowhere(): void
    {
        // Given
        $user = Fixtures::user();
        $consents = new InMemoryConsentRepository();
        $consent = self::consent($user, 'oidc-demo');
        $consent->revoke(Fixtures::now());
        $consents->save($consent);
        $consents->save(self::consent($user, 'another-app'));

        // When
        $state = new ConsentsSection($consents)->state($user);

        // Then
        static::assertSame(
            [
                'count' => 1,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function theLinkOpensThePageOfTheConsents(): void
    {
        // Given
        $section = self::section();

        // When
        $route = $section->route();

        // Then
        static::assertSame('beffroi_interaction_account_consents', $route);
    }

    /**
     * @param list<string> $clientIds
     */
    private static function section(?User $user = null, array $clientIds = []): ConsentsSection
    {
        $consents = new InMemoryConsentRepository();
        foreach ($clientIds as $clientId) {
            $consents->save(self::consent($user ?? Fixtures::user(), $clientId));
        }

        return new ConsentsSection($consents);
    }

    private static function consent(User $user, string $clientId): Consent
    {
        return new Consent(
            Uuid::v7(),
            $user,
            Clients::confidential($user->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: $clientId),
            new Scopes([new Scope('openid')]),
            Fixtures::now(),
        );
    }
}
