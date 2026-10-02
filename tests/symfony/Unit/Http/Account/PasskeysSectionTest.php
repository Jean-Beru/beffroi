<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http\Account;

use Beffroi\Bundle\Http\Account\PasskeysSection;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What the home of the account says of the passkeys of a user: how many still sign them in.
 */
final class PasskeysSectionTest extends TestCase
{
    #[Test]
    public function anAccountWithoutAPasskeyIsSaidToHoldNone(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section();

        // When
        $state = $section->state($user);

        // Then
        static::assertSame('account.passkeys.state', $state->key);
        static::assertSame(
            [
                'count' => 0,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function thePasskeysOfTheAccountAreCounted(): void
    {
        // Given
        $user = Fixtures::user();
        $section = self::section([
            Fixtures::passkey($user, 'YubiKey 5', 'first'),
            Fixtures::passkey($user, 'Phone', 'second'),
        ]);

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
    public function aRevokedPasskeyIsCountedNowhere(): void
    {
        // Given
        $user = Fixtures::user();
        $revoked = Fixtures::passkey($user, 'Lost key', 'first');
        $revoked->revoke(Fixtures::now());
        $section = self::section([$revoked, Fixtures::passkey($user, 'Phone', 'second')]);

        // When
        $state = $section->state($user);

        // Then
        static::assertSame(
            [
                'count' => 1,
            ],
            $state->parameters,
        );
    }

    #[Test]
    public function theLinkOpensThePageOfThePasskeys(): void
    {
        // Given
        $section = self::section();

        // When
        $route = $section->route();

        // Then
        static::assertSame('beffroi_interaction_account_passkeys', $route);
    }

    /**
     * @param list<Credential> $credentials
     */
    private static function section(array $credentials = []): PasskeysSection
    {
        $repository = new InMemoryCredentialRepository();
        foreach ($credentials as $credential) {
            $repository->save($credential);
        }

        return new PasskeysSection(new ActiveCredentials($repository));
    }
}
