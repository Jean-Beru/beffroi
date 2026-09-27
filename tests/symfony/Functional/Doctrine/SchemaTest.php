<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use Doctrine\DBAL\Schema\Name\OptionallyQualifiedName;
use Doctrine\DBAL\Schema\Table;
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
        'heidi_passkey_credential',
        'heidi_totp_credential',
        'heidi_linked_identity',
        'heidi_push_subscription',
        'heidi_group',
        'heidi_group_membership',
        'heidi_authentication_session',
        'heidi_interaction',
        'heidi_authorization_code',
        'heidi_pushed_authorization_request',
        'heidi_device_authorization_request',
        'heidi_backchannel_authentication_request',
        'heidi_refresh_token',
        'heidi_access_token',
        'heidi_client_access_token',
        'heidi_subject_access_token',
        'heidi_consent',
    ];

    /**
     * What "doctrine:schema:validate" checks: the mappings are consistent, and the database matches them.
     */
    #[Test]
    public function theMappingsAreValid(): void
    {
        // Given
        $validator = new SchemaValidator(self::entityManager());

        // When / Then
        static::assertSame([], $validator->validateMapping());
    }

    #[Test]
    public function theSchemaIsInSyncWithTheMappings(): void
    {
        // Given
        $validator = new SchemaValidator(self::entityManager());

        // When / Then
        static::assertSame([], $validator->getUpdateSchemaList());
    }

    /**
     * Architecture §5.3: the tables of the bundle, every one prefixed "heidi_", and no other.
     */
    #[Test]
    public function theBundleDeclaresItsTwentyPrefixedTables(): void
    {
        // When
        $tables = array_keys(self::tablesOfTheBundle());

        // Then
        $expected = self::TABLES;
        sort($tables);
        sort($expected);
        static::assertSame($expected, $tables);
        foreach ($tables as $name) {
            static::assertTrue(str_starts_with($name, 'heidi_'), $name);
        }
    }

    /**
     * Architecture §5.3: every row carries the tenant.
     */
    #[Test]
    public function everyTableButTheTenantOneCarriesTheTenant(): void
    {
        // When
        $tables = self::tablesOfTheBundle();

        // Then
        unset($tables['heidi_tenant']);
        static::assertNotSame([], $tables);
        foreach ($tables as $name => $table) {
            static::assertTrue($table->hasColumn('tenant_id'), $name);
            static::assertNotFalse($table->getColumn('tenant_id')->getNotnull(), $name);
        }
    }

    /**
     * Decision 0002: the host application keeps its own "User", in a table of its own, and the bundle
     * never hooks onto it. The two schemas install together.
     */
    #[Test]
    public function theHostApplicationKeepsItsOwnUserNextToTheBundle(): void
    {
        // Given
        $host = new HostUser('host@example.com');
        self::entityManager()->persist($host);
        self::entityManager()->flush();
        self::reload();

        // When
        $tables = array_map(static fn (OptionallyQualifiedName $table): string => $table
            ->getUnqualifiedName()
            ->getValue(), self::entityManager()->getConnection()->createSchemaManager()->introspectTableNames());

        // Then
        static::assertContains('app_user', $tables);
        static::assertContains('heidi_user', $tables);
        static::assertSame('host@example.com', self::entityManager()->find(HostUser::class, $host->id)?->email);
    }

    /**
     * The tables the mappings of the bundle describe, by name, the one of the host application left out.
     *
     * @return array<string, Table>
     */
    private static function tablesOfTheBundle(): array
    {
        $entityManager = self::entityManager();
        $schema = new SchemaTool($entityManager)->getSchemaFromMetadata($entityManager->getMetadataFactory()->getAllMetadata());
        $tables = [];
        foreach ($schema->getTables() as $table) {
            $name = $table->getObjectName()->getUnqualifiedName()->getValue();
            if ($name !== 'app_user') {
                $tables[$name] = $table;
            }
        }

        return $tables;
    }
}
