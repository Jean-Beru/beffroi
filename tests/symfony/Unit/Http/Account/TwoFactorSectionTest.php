<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Account;

use App\Http\Account\TwoFactorSection;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
        static::assertSame('beffroi_interaction_account_two_factor', $route);
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
