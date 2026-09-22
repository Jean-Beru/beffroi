<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Core\Domain\Credential\Credential;
use Heidi\Core\Domain\Credential\ExternallyIdentifiedCredentialInterface;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Port\CredentialRepositoryInterface;
use function is_a;
use function is_subclass_of;
use LogicException;
use function sort;
use function sprintf;
use Symfony\Component\Uid\Uuid;
use function usort;

/**
 * Credentials, one table per kind (architecture §3.4, §5.3): the kinds are the entities mapped under
 * Credential, read once from the metadata; a kind asked for is read from its table, every kind from all of
 * them and listed together, oldest first. A kind presented by an identifier of its own maps it as
 * "externalId", the property ExternallyIdentifiedCredentialInterface asks for; nothing here names a kind.
 */
final class DoctrineCredentialRepository implements CredentialRepositoryInterface
{
    /**
     * @var list<class-string<Credential>>|null
     */
    private ?array $kinds = null;

    public function __construct(
        private readonly ManagerRegistry $registry,
    ) {
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return list<T>
     */
    public function findByUser(User $user, string $kind = Credential::class): array
    {
        $credentials = [];
        foreach ($this->kinds() as $class) {
            if (! is_a($class, $kind, true)) {
                continue;
            }
            $credentials = array_merge($credentials, $this->manager($class)
                ->getRepository($class)
                ->findBy([
                    'user' => $user,
                ], [
                    'createdAt' => 'ASC',
                    'id' => 'ASC',
                ]));
        }
        usort($credentials, static fn (Credential $a, Credential $b): int => $a->createdAt <=> $b->createdAt);

        return array_values(array_filter($credentials, static fn (Credential $credential): bool => $credential instanceof $kind));
    }

    public function find(Uuid $id): ?Credential
    {
        foreach ($this->kinds() as $class) {
            $credential = $this->manager($class)->find($class, $id);
            if ($credential !== null) {
                return $credential;
            }
        }

        return null;
    }

    /**
     * @template T of Credential
     *
     * @param class-string<T> $kind
     *
     * @return T|null
     */
    public function findByExternalId(Tenant $tenant, string $kind, string $externalId): ?Credential
    {
        if (! is_a($kind, ExternallyIdentifiedCredentialInterface::class, true)) {
            throw new InvalidArgumentException(sprintf('A credential of kind "%s" is not presented by an identifier.', $kind));
        }

        return $this->manager($kind)
            ->getRepository($kind)
            ->findOneBy([
                'tenant' => $tenant,
                'externalId' => $externalId,
            ]);
    }

    public function save(Credential $credential): void
    {
        $manager = $this->manager($credential::class);
        $manager->persist($credential);
        $manager->flush();
    }

    /**
     * The entities mapped under Credential, in a fixed order.
     *
     * @return list<class-string<Credential>>
     */
    private function kinds(): array
    {
        if ($this->kinds !== null) {
            return $this->kinds;
        }
        $kinds = [];
        foreach ($this->registry->getManagers() as $manager) {
            foreach ($manager->getMetadataFactory()->getAllMetadata() as $metadata) {
                $class = $metadata->getName();
                if (is_subclass_of($class, Credential::class)) {
                    $kinds[] = $class;
                }
            }
        }
        sort($kinds);

        return $this->kinds = $kinds;
    }

    /**
     * @param class-string<Credential> $class
     */
    private function manager(string $class): EntityManagerInterface
    {
        $manager = $this->registry->getManagerForClass($class);
        if (! $manager instanceof EntityManagerInterface) {
            throw new LogicException(sprintf('No entity manager maps "%s".', $class));
        }

        return $manager;
    }
}
