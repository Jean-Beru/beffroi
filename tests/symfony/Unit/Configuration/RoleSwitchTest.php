<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Configuration;

use function array_map;
use Beffroi\Bundle\Configuration\RoleSwitch;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * Decision 0030: a role the deployment plays is read once, when the container builds a service the role changes, and
 * what that service is handed then is the handler of the role or none.
 */
final class RoleSwitchTest extends TestCase
{
    /**
     * Spec/saml.md S-40: the SAML key is the key of both SAML roles, so it is wanted while either is on.
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
     * Spec/saml.md S-41: a role that is on hands over the service it builds.
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
     * Spec/saml.md S-41: a role that is off hands over none, and builds nothing of what it would have handed over.
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
