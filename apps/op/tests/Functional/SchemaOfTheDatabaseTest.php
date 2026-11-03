<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Doctrine\Deprecations\PHPUnit\VerifyDeprecations;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\ApplicationTester;

/**
 * Issue #976: "doctrine:schema:validate" on the database the migrations of the bundle built, on PostgreSQL,
 * which is what an operator runs and what "doctrine:migrations:diff" compares the same way. DBAL 4 reads a
 * JSONB column back as the "json" type carrying the "jsonb" platform option, which it deprecates
 * (doctrine/dbal#6939), and declares it through that option to compare it; the connection of this application
 * maps the type of the database to the JSONB type of the mappings, which is how DBAL 5 reads it
 * (doctrine/dbal#6942).
 *
 * The command runs through the console of the application rather than alone: the console event is what has
 * DoctrineMigrationsBundle leave its own table out of the comparison. The schema is the one "castor
 * app-phpunit" migrated before the suite, as a deployment is migrated; nothing here writes a row.
 */
final class SchemaOfTheDatabaseTest extends KernelTestCase
{
    use VerifyDeprecations;

    #[Test]
    public function theDatabaseTheMigrationsBuiltIsWhatTheMappingsDescribe(): void
    {
        // Given
        $console = self::console();

        // When
        $status = $console->run([
            'command' => 'doctrine:schema:validate',
            '-vv' => true,
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $status, $console->getDisplay());
    }

    #[Test]
    public function validatingTheSchemaRaisesNoDeprecationOfDoctrine(): void
    {
        // Given
        $console = self::console();

        // Then
        $this->expectNoDeprecationWithIdentifier('https://github.com/doctrine/dbal/pull/6939');

        // When
        $console->run([
            'command' => 'doctrine:schema:validate',
        ]);
    }

    private static function console(): ApplicationTester
    {
        $application = new Application(self::bootKernel());
        $application->setAutoExit(false);

        return new ApplicationTester($application);
    }
}
