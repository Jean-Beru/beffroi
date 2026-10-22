<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Port\GroupRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0002, issue #782: the groups of a tenant in beffroi_group, found by the name the console created
 * them under and the declaration of an upstream provider maps to.
 */
final class GroupsTest extends DatabaseTestCase
{
    #[Test]
    public function aGroupSavedIsFoundByItsName(): void
    {
        // Given
        $group = new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now());
        self::groupsOfTheTenant()->save($group);
        self::reload();

        // When
        $found = self::groupsOfTheTenant()->findByName(self::tenant(), 'admins');

        // Then
        static::assertNotNull($found);
        static::assertTrue($found->id->equals($group->id));
        static::assertSame(GroupSource::Local, $found->source);
    }

    #[Test]
    #[DataProvider('provideOtherNames')]
    public function anotherNameFindsNothing(string $name): void
    {
        // Given
        self::groupsOfTheTenant()->save(new Group(Uuid::v7(), self::tenant(), 'admins', GroupSource::Local, self::now()));
        self::reload();

        // When / Then
        static::assertNull(self::groupsOfTheTenant()->findByName(self::tenant(), $name));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherNames(): iterable
    {
        yield 'another case' => ['Admins'];
        yield 'another name' => ['sales'];
    }

    private static function groupsOfTheTenant(): GroupRepositoryInterface
    {
        return self::service('test.beffroi.groups', GroupRepositoryInterface::class);
    }
}
