<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Group;

use Beffroi\Core\Application\Group\GroupAlreadyExistsException;
use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Decision 0002, issue #782: the groups of a tenant are created by the deployment, from a console, a fixture or
 * an import, never from what an upstream provider sends.
 */
final class GroupProvisionerTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryGroupRepository $groups;

    private MockClock $clock;

    private GroupProvisioner $provisioner;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->groups = new InMemoryGroupRepository();
        $this->clock = new MockClock('2026-10-22T12:00:00+00:00');
        $this->provisioner = new GroupProvisioner($this->groups, new SymfonyUuidGenerator(), $this->clock);
    }

    #[Test]
    public function aGroupIsCreatedLocalInTheTenant(): void
    {
        // When
        $group = $this->provisioner->create($this->tenant, 'admins');

        // Then
        static::assertSame($group, $this->groups->findByName($this->tenant, 'admins'));
        static::assertSame($this->tenant, $group->tenant);
        static::assertSame('admins', $group->name);
        static::assertSame(GroupSource::Local, $group->source);
        static::assertEquals($this->clock->now(), $group->createdAt);
    }

    #[Test]
    public function theNameIsTakenWithoutTheSpacesAroundIt(): void
    {
        // When
        $group = $this->provisioner->create($this->tenant, '  admins ');

        // Then
        static::assertSame('admins', $group->name);
    }

    #[Test]
    #[DataProvider('provideNamesAlreadyTaken')]
    public function aNameAlreadyTakenInTheTenantIsRefused(string $again): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'admins');

        // Then
        $this->expectException(GroupAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A group named "admins" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, $again);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesAlreadyTaken(): iterable
    {
        yield 'the same name' => ['admins'];
        yield 'the same name with spaces around it' => [' admins '];
    }

    #[Test]
    public function aNameIsTakenInItsTenantOnly(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->provisioner->create($other, 'admins');

        // When
        $group = $this->provisioner->create($this->tenant, 'admins');

        // Then
        static::assertSame($group, $this->groups->findByName($this->tenant, 'admins'));
    }

    #[Test]
    public function anEmptyNameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A group name must not be empty.');

        // When
        $this->provisioner->create($this->tenant, '   ');
    }

    #[Test]
    public function aGroupOfAnotherNameIsNotFound(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'admins');

        // When / Then
        static::assertNull($this->groups->findByName($this->tenant, 'Admins'));
    }
}
