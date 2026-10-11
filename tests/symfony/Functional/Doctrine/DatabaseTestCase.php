<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Closure;
use function copy;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\Persistence\ManagerRegistry;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\TenantSynchronizer;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Domain\Session\AuthenticationPredicateInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use function is_string;
use function sprintf;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A kernel on a fresh SQLite schema (architecture §7), the tenant of the configuration synchronised, so
 * that a test starts where an application starts after its first migration and its provisioning. A test
 * that drives a browser gets it from browser(): the kernel is then the one behind the browser, and the
 * rows survive the reboot the browser does between two requests.
 */
abstract class DatabaseTestCase extends WebTestCase
{
    protected function setUp(): void
    {
        self::bootKernel();
        self::prepareDatabase();
    }

    /**
     * A browser on a kernel of its own, the schema and the tenant prepared behind it. What configures the
     * container is applied again after every reboot the browser does between two requests, which is how a
     * test replaces a service for the life of the browser.
     *
     * @param (Closure(ContainerInterface): void)|null $configureContainer
     * @param array<string, mixed> $options what the kernel behind the browser is booted with
     */
    protected static function browser(?Closure $configureContainer = null, array $options = []): KernelBrowser
    {
        self::ensureKernelShutdown();
        $browser = self::createClient(
            $configureContainer === null
                ? $options
                : [
                    ...$options,
                    'configure_container' => $configureContainer,
                ],
        );
        self::prepareDatabase();

        return $browser;
    }

    /**
     * The database file of the first test of the process, once its schema is created and its tenant
     * synchronised, kept beside it as the template every later test starts from: a copy of the file, a
     * millisecond, where the schema dropped and created by every test was 160 ms of its time. The
     * template is rebuilt by every process, never trusted from a previous run.
     */
    private static ?string $template = null;

    /**
     * Where the bundle writes the sealed keys of the tenant of the suite, which config_test.yml points at
     * "%kernel.cache_dir%/keys". Read from the container and not restated, so that the directory is the one
     * the kernel of this process was given, token of a parallel worker included.
     */
    protected static function keyStorage(): string
    {
        $cacheDirectory = static::getContainer()->getParameter('kernel.cache_dir');
        if (! is_string($cacheDirectory)) {
            static::fail('The cache directory of the test kernel is not a path.');
        }

        return $cacheDirectory . '/keys';
    }

    private static function prepareDatabase(): void
    {
        $connection = self::entityManager()->getConnection();
        $connection->close();
        $database = static::getContainer()->getParameter('beffroi_test.database');
        if (! is_string($database)) {
            static::fail('The database of the test kernel is not a file.');
        }
        if (self::$template === null) {
            self::createDatabase();
            $connection->close();
            self::$template = $database . '.template';
            copy($database, self::$template) || static::fail('The template of the database was not written.');
        } else {
            copy(self::$template, $database) || static::fail('The database was not restored from its template.');
        }
        self::entityManager()->clear();
    }

    /**
     * The schema is dropped and created in one transaction: SQLite syncs the file once instead of once per
     * statement, the difference between 40 ms and 400 ms.
     */
    private static function createDatabase(): void
    {
        $entityManager = self::entityManager();
        $schema = new SchemaTool($entityManager);
        $entityManager->wrapInTransaction(static function () use ($entityManager, $schema): void {
            $schema->dropDatabase();
            $schema->createSchema($entityManager->getMetadataFactory()->getAllMetadata());
        });
        self::service('test.beffroi.tenant_synchronizer', TenantSynchronizer::class)->synchronize();
    }

    protected static function entityManager(): EntityManagerInterface
    {
        return self::service('doctrine.orm.entity_manager', EntityManagerInterface::class);
    }

    protected static function registry(): ManagerRegistry
    {
        return self::service('doctrine', ManagerRegistry::class);
    }

    protected static function managers(): EntityManagers
    {
        return new EntityManagers(self::registry());
    }

    /**
     * The tenant of the current unit of work; reload() forgets it with the rest.
     */
    protected static function tenant(): Tenant
    {
        return self::service('test.beffroi.tenant_provider', TenantProvider::class)->provide();
    }

    /**
     * The tenant names the floor of its logins, as an administrator does from the console (issue #327):
     * the act itself, so that what the tests read is a tenant hardened the one way a tenant hardens, the
     * credentials it forbids forgotten with it.
     *
     * @return int how many credentials the floor forbade
     */
    protected static function harden(AuthenticationPredicateInterface $floor): int
    {
        return self::service('test.beffroi.tenant_hardening', TenantHardening::class)->adopt(self::tenant(), $floor, self::context());
    }

    /**
     * A moment with the precision of a datetime column, so that what goes in comes out equal.
     */
    protected static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-15T10:00:00+00:00');
    }

    protected static function context(?DateTimeImmutable $receivedAt = null): RequestContext
    {
        return new RequestContext($receivedAt ?? self::now(), SealedRows::IP_ADDRESS, SealedRows::USER_AGENT);
    }

    /**
     * A user of the configured tenant, saved.
     */
    protected static function user(string $username = 'alice', string $subject = 'alice-subject'): User
    {
        $user = User::create(Uuid::v7(), self::tenant(), new Subject($subject), $username, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($user);

        return $user;
    }

    /**
     * A session of the user opened with a password at the given moment, saved.
     */
    protected static function session(User $user, ?DateTimeImmutable $establishedAt = null): AuthenticationSession
    {
        $establishedAt ??= self::now();
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            $establishedAt,
            AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt),
            self::context($establishedAt),
            $establishedAt->modify('+12 hours'),
        );
        self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->save($session);

        return $session;
    }

    /**
     * A client of the configuration of the test kernel.
     */
    protected static function client(string $clientId = 'oidc-demo'): Client
    {
        return (
            self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId) ?? static::fail(sprintf(
                'The client "%s" is not configured.',
                $clientId,
            ))
        );
    }

    /**
     * Forgets every managed object, the tenant included, so that the next lookup reads the rows and not
     * the identity map: what was held before is detached and must not be saved again.
     */
    protected static function reload(): void
    {
        self::entityManager()->clear();
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    protected static function service(string $id, string $class): object
    {
        $service = self::getContainer()->get($id);
        static::assertInstanceOf($class, $service);

        return $service;
    }
}
