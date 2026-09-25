<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http\Account;

use Heidi\Bundle\Http\Account\TwoFactorSection;
use Heidi\Core\Application\Credential\ActiveCredentials;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\Credential;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What the home of the account says of the second factor of a user: the authenticator app it holds, or none.
 * How many backup codes are left is on the page of the second factor, where they can be renewed.
 */
final class TwoFactorSectionTest extends TestCase
{
    #[Test]
    public function anAccountWithoutAnAuthenticatorAppIsSaidToHoldNone(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section();

        // When
        $state = $section->state($user);

        // Then
        static::assertSame('account.two_factor.state.none', $state->key);
        static::assertSame([], $state->parameters);
    }

    #[Test]
    public function anAccountWithAnAuthenticatorAppIsSaidToHoldOne(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section([Totps::credential($user, new FakePasswordHasher())]);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame('account.two_factor.state.active', $state->key);
    }

    #[Test]
    public function anAuthenticatorAppThatWasRemovedIsNoLongerHeld(): void
    {
        // Given
        $user = Fixtures::user();
        $totp = Totps::credential($user, new FakePasswordHasher());
        $totp->revoke(Fixtures::now());
        $section = self::section([$totp]);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame('account.two_factor.state.none', $state->key);
    }

    #[Test]
    public function theLinkOpensThePageOfTheSecondFactor(): void
    {
        // Given
        $section = self::section();

        // When
        $route = $section->route();

        // Then
        static::assertSame('heidi_interaction_account_two_factor', $route);
    }

    /**
     * @param list<Credential> $credentials
     */
    private static function section(array $credentials = []): TwoFactorSection
    {
        $repository = new InMemoryCredentialRepository();
        foreach ($credentials as $credential) {
            $repository->save($credential);
        }

        return new TwoFactorSection(new ActiveTotp(new ActiveCredentials($repository)));
    }
}
