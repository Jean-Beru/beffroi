<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Group;

use Heidi\Core\Domain\Group\Group;
use Heidi\Core\Domain\Group\GroupMembership;
use Heidi\Core\Domain\Group\GroupSource;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class GroupMembershipTest extends TestCase
{
    #[Test]
    public function aUserJoinsAGroupOfTheirOwnTenant(): void
    {
        $tenant = Fixtures::tenant();
        $group = new Group(Uuid::v7(), $tenant, 'admins', GroupSource::Local, Fixtures::now());

        $membership = new GroupMembership(Uuid::v7(), $group, Fixtures::user($tenant), GroupSource::UpstreamClaims, Fixtures::now());

        static::assertTrue($membership->source->isManaged());
        static::assertFalse($group->source->isManaged());
    }

    #[Test]
    public function aUserCannotJoinAGroupOfAnotherTenant(): void
    {
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());
        $stranger = Fixtures::user(Fixtures::tenant('other', 'https://id.other.example'));

        $this->expectException(InvalidArgumentException::class);

        new GroupMembership(Uuid::v7(), $group, $stranger, GroupSource::Local, Fixtures::now());
    }

    #[Test]
    public function aGroupCanBeRenamedButNotToNothing(): void
    {
        $group = new Group(Uuid::v7(), Fixtures::tenant(), 'admins', GroupSource::Local, Fixtures::now());
        $group->rename('administrators');
        static::assertSame('administrators', $group->name);

        $this->expectException(InvalidArgumentException::class);
        $group->rename('');
    }

    #[Test]
    public function aGroupNameIsNeverEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Group(Uuid::v7(), Fixtures::tenant(), '', GroupSource::Local, Fixtures::now());
    }
}
