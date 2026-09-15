<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use Doctrine\DBAL\Schema\Name\OptionallyQualifiedName;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\ORM\Tools\SchemaValidator;
use Heidi\Bundle\Tests\Functional\Doctrine\Host\User as HostUser;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function str_starts_with;

/**
 * The mappings of the bundle describe a schema Doctrine validates, creates on SQLite and finds in sync
 * afterwards (architecture §5.3, §7), next to the tables of a host application (decision 0002).
 */
final class SchemaTest extends DatabaseTestCase
{
    public const array TABLES = [
        'heidi_tenant',
        'heidi_user',
        'heidi_password_credential',
        'heidi_linked_identity',
        'heidi_group',
        'heidi_group_membership',
        'heidi_authentication_session',
        'heidi_interaction',
        'heidi_authorization_code',
        'heidi_refresh_token',
        'heidi_consent',
    ];

    /**
     * What "doctrine:schema:validate" checks: the mappings are consistent, and the database matches them.
     */
    #[Test]
    public function theMappingsAreValidAndTheSchemaIsInSync(): void
    {
        $validator = new SchemaValidator(self::entityManager());

        static::assertSame([], $validator->validateMapping());
        static::assertSame([], $validator->getUpdateSchemaList());
    }

    /**
     * Architecture §5.3: every table is prefixed "heidi_" and every row carries the tenant.
     */
    #[Test]
    public function everyTableIsPrefixedAndCarriesTheTenant(): void
    {
        $entityManager = self::entityManager();
        $schema = new SchemaTool($entityManager)
            ->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata());

        $tables = [];
        foreach ($schema->getTables() as $table) {
            $name = $table->getObjectName()
                ->getUnqualifiedName()
                ->getValue();
            if ($name === 'app_user') {
                continue;
            }
            $tables[] = $name;
            static::assertTrue(str_starts_with($name, 'heidi_'), $name);
            if ($name !== 'heidi_tenant') {
                static::assertTrue($table->hasColumn('tenant_id'), $name);
                static::assertNotFalse($table->getColumn('tenant_id')->getNotnull(), $name);
            }
        }
        $expected = self::TABLES;
        sort($tables);
        sort($expected);
        static::assertSame($expected, $tables);
    }

    /**
     * Decision 0002: the host application keeps its own "User", in a table of its own, and the bundle
     * never hooks onto it. The two schemas install together.
     */
    #[Test]
    public function theHostApplicationKeepsItsOwnUserNextToTheBundle(): void
    {
        $entityManager = self::entityManager();
        $host = new HostUser('host@example.com');
        $entityManager->persist($host);
        $entityManager->flush();
        self::reload();

        $tables = array_map(static fn (OptionallyQualifiedName $table): string => $table->getUnqualifiedName()->getValue(), self::entityManager()->getConnection()->createSchemaManager()->introspectTableNames());
        sort($tables);

        static::assertContains('app_user', $tables);
        static::assertContains('heidi_user', $tables);
        static::assertSame('host@example.com', $entityManager->find(HostUser::class, $host->id)?->email);
    }
}
