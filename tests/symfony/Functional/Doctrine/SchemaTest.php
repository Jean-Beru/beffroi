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
        'heidi_client',
        'heidi_initial_access_token',
        'heidi_pairwise_subject',
        // The one table of this schema no mapping of the bundle describes: the store of the data keys puts
        // it there, through the schema listener of the ORM bridge, so that "doctrine:schema:update" does
        // not offer to drop what it did not put there (decisions 0011 and 0018).
        'heidi_data_key',
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
    public function theBundleDeclaresItsTwentyThreePrefixedTables(): void
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
     *
     * Two tables name it otherwise, and both are named here rather than letting the rule bend. The tenant
     * is its own row. And the store of the data keys carries the tenant in its scope, as the slug the
     * encrypter of the bundle prefixes the family of columns with (decision 0018): the five columns of
     * that table are the five the store of the bridge names, a table carrying anything else being a table
     * the application would have to declare itself, and the scope is the only channel there is between an
     * encrypted type and the store.
     */
    #[Test]
    public function everyTableButTheTenantOneAndTheDataKeysCarriesTheTenant(): void
    {
        // When
        $tables = self::tablesOfTheBundle();

        // Then
        unset($tables['heidi_tenant'], $tables['heidi_data_key']);
        static::assertNotSame([], $tables);
        foreach ($tables as $name => $table) {
            static::assertTrue($table->hasColumn('tenant_id'), $name);
            static::assertNotFalse($table->getColumn('tenant_id')->getNotnull(), $name);
        }
    }

    /**
     * The scope of the data key store is what carries the tenant there, so a table with no tenant column
     * is refused unless it is one of the two the rule above names: this is the assertion that makes the
     * exception an exception rather than a hole.
     */
    #[Test]
    public function theScopeOfTheDataKeyStoreIsWhatCarriesTheTenantThere(): void
    {
        // When
        $table = self::tablesOfTheBundle()['heidi_data_key'] ?? null;

        // Then
        static::assertNotNull($table);
        static::assertFalse($table->hasColumn('tenant_id'));
        static::assertTrue($table->hasColumn('scope'));
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
