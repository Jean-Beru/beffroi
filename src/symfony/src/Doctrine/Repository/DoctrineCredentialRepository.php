<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\ExternallyIdentifiedCredentialInterface;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Port\CanPageCredentialsInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use function is_a;
use function is_subclass_of;
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
final class DoctrineCredentialRepository implements CanPageCredentialsInterface, CredentialRepositoryInterface
{
    /**
     * @var list<class-string<Credential>>|null
     */
    private ?array $kinds = null;

    public function __construct(
        private readonly EntityManagers $managers,
    ) {
    }

    /**
     * One store per kind answers here and the order is made of their answers, so the page is taken of what
     * they gave and not of a table: a person holds a handful of credentials of a kind, never a journal.
     *
     * @param class-string<Credential> $kind
     *
     * @return Listing<Credential>
     */
    public function pageOfCredentials(User $user, string $kind, Pagination $pagination): Listing
    {
        return Listing::of($this->findByUser($user, $kind), $pagination);
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
            $credentials = array_merge($credentials, $this->managers
                ->forClass($class)
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
            $credential = $this->managers->forClass($class)->find($class, $id);
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

        return $this->managers
            ->forClass($kind)
            ->getRepository($kind)
            ->findOneBy([
                'tenant' => $tenant,
                'externalId' => $externalId,
            ]);
    }

    public function save(Credential $credential): void
    {
        $manager = $this->managers->forClass($credential::class);
        $manager->persist($credential);
        $manager->flush();
    }

    /**
     * The entities mapped under Credential, in a fixed order: what has a table of its own, and so a kind
     * a user may hold. A mapped superclass is not one (RevocableCredential is where a kind that can be
     * revoked takes its revocation from, not a kind), and asking its repository for rows would name a
     * table nothing ever created.
     *
     * @return list<class-string<Credential>>
     */
    private function kinds(): array
    {
        if ($this->kinds !== null) {
            return $this->kinds;
        }
        $kinds = [];
        foreach ($this->managers->all() as $manager) {
            foreach ($manager->getMetadataFactory()->getAllMetadata() as $metadata) {
                if ($metadata instanceof OrmClassMetadata && $metadata->isMappedSuperclass) {
                    continue;
                }
                $class = $metadata->getName();
                if (is_subclass_of($class, Credential::class)) {
                    $kinds[] = $class;
                }
            }
        }
        sort($kinds);

        return $this->kinds = $kinds;
    }
}
