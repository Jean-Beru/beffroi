<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine;

use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AtomicWritesInterface;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #781: a person an upstream provider creates is the person, its source and its linked identity, kept
 * all or none. A person kept without the identity that names it would be a person no sign-in finds, whose
 * address refuses every creation after it.
 */
final class JustInTimeProvisioningTest extends DatabaseTestCase
{
    private const string ADDRESS = 'alice@acme.example';

    /**
     * The store of linked identities finds through Doctrine and refuses every write, counting them: the
     * failure comes after the person was written, in the same transaction, and must take it back.
     */
    #[Test]
    public function aPersonWhoseLinkedIdentityFailsToBeWrittenIsNotKept(): void
    {
        // Given
        $identities = new class(self::service('test.beffroi.linked_identities', LinkedIdentityRepositoryInterface::class)) implements
            LinkedIdentityRepositoryInterface {
            public private(set) int $refused = 0;

            public function __construct(
                private readonly LinkedIdentityRepositoryInterface $stored,
            ) {
            }

            public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
            {
                return $this->stored->find($tenant, $provider, $subject);
            }

            public function save(LinkedIdentity $identity): void
            {
                ++$this->refused;

                throw new RuntimeException('The linked identity could not be written.');
            }
        };
        $clock = new MockClock(self::now());
        $provisioning = new JustInTimeProvisioning(
            $identities,
            self::users(),
            self::service('test.beffroi.user_provisioner', UserProvisioner::class),
            new IdentityLinker($identities, new SymfonyUuidGenerator(), $clock),
            new RecordingEventDispatcher(),
            $clock,
            self::service('test.beffroi.atomic_writes', AtomicWritesInterface::class),
        );

        // When
        try {
            $provisioning->personNamedBy(
                self::tenant(),
                new UpstreamProvider('https://idp.acme.example/saml', ['acme.example'], ['given_name']),
                'a7f3c2e1-alice',
                new EmailAddress(self::ADDRESS),
                [
                    'given_name' => 'Alice',
                ],
                self::context(),
            );
        } catch (RuntimeException) {
        }

        // Then
        static::assertSame(1, $identities->refused);
        self::reload();
        static::assertNull(self::users()->findByEmail(self::tenant(), new EmailAddress(self::ADDRESS)));
        static::assertNull(self::users()->findByUsername(self::tenant(), self::ADDRESS));
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.beffroi.users', UserRepositoryInterface::class);
    }
}
