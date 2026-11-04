<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use function array_map;
use App\Configuration\RoleSwitch;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Decision 0030
 */
final class RoleSwitchTest extends TestCase
{
    /**
     * spec/saml.md S-40
     *
     * @param list<bool> $roles
     */
    #[Test]
    #[DataProvider('provideRoles')]
    public function aRoleOfSeveralIsOnWhileAnyOfThemIs(array $roles, bool $on): void
    {
        // When
        $role = RoleSwitch::anyOf(array_map(static fn (bool $on): RoleSwitch => new RoleSwitch($on), $roles));

        // Then
        static::assertSame($on, $role->on);
    }

    /**
     * @return iterable<string, array{list<bool>, bool}>
     */
    public static function provideRoles(): iterable
    {
        yield 'neither' => [[false, false], false];
        yield 'the first' => [[true, false], true];
        yield 'the second' => [[false, true], true];
        yield 'both' => [[true, true], true];
    }

    /**
     * spec/saml.md S-41
     */
    #[Test]
    public function aRoleThatIsOnHandsOverItsService(): void
    {
        // Given
        $service = new stdClass();

        // When
        $served = new RoleSwitch(true)->served(static fn (): stdClass => $service);

        // Then
        static::assertSame($service, $served);
    }

    /**
     * spec/saml.md S-41
     */
    #[Test]
    public function aRoleThatIsOffHandsOverNoneAndBuildsNothing(): void
    {
        // When
        $served = new RoleSwitch(false)->served(static fn (): stdClass => self::fail('A role that is off builds nothing.'));

        // Then
        static::assertNull($served);
    }
}
