<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Configuration;

use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Decision 0038: the groups a deployment names to administer the tenant it declares.
 */
final class ConfigurationAdministratorGroupsTest extends TestCase
{
    #[Test]
    public function theGroupsAreTheOnesOfTheTenantTheDeploymentDeclares(): void
    {
        // Given
        $groups = new ConfigurationAdministratorGroups('acme', ['administrators', 'operators', 'administrators']);

        // When
        $named = $groups->groupsAdministering(Fixtures::tenant('acme'));

        // Then
        static::assertSame(['administrators', 'operators'], $named);
    }

    #[Test]
    public function anotherTenantIsAdministeredByNobody(): void
    {
        // Given
        $groups = new ConfigurationAdministratorGroups('acme', ['administrators']);

        // When
        $named = $groups->groupsAdministering(Fixtures::tenant('globex'));

        // Then
        static::assertSame([], $named);
    }

    #[Test]
    #[DataProvider('provideNamesNoGroupCarries')]
    public function aNameNoGroupCarriesRefusesTheConstruction(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The group "%s" is named to administer the tenant "acme", and no group carries a name that is empty or begins or ends with whitespace.',
            $name,
        ));

        // When
        new ConfigurationAdministratorGroups('acme', [$name]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesNoGroupCarries(): iterable
    {
        yield 'an empty name' => [''];
        yield 'a name that begins with a space' => [' administrators'];
        yield 'a name that ends with a line feed' => ["administrators\n"];
    }
}
