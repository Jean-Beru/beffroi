<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use function sprintf;

/**
 * Interactions in beffroi_interaction (architecture §4.3). An interaction of a client no longer registered
 * is not found.
 *
 * @extends DoctrineRepository<Interaction>
 */
final readonly class DoctrineInteractionRepository extends DoctrineRepository implements DeadRecordsInterface, InteractionRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
    ) {
        parent::__construct($managers, Interaction::class);
    }

    /**
     * An interaction is the authorization request parked while the user logs in and consents (architecture
     * §4.3), so it is worth nothing once it cannot be resumed, which is its expiry whether it was completed
     * before it or abandoned (issue #177). The expiry and not the completion: a request granted seconds
     * before the page is reloaded is still answered from the row, and one date an index reads is what a
     * sweep can ask of a table.
     *
     * Nothing waits on it: the session and the consent it names are its own columns, dropped to null
     * rather than cascading, and the authorization code carries what the token endpoint needs of its own.
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $expiry = $this->sweep->column(Interaction::class, 'expiresAt');

        return $this->sweep->from(
            Interaction::class,
            $tenant,
            sprintf('%s <= :now', $expiry),
            $expiry,
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
    }

    public function find(string $id): ?Interaction
    {
        $interaction = $this->repository()->findOneBy([
            'id' => $id,
        ]);

        return $interaction !== null && ClientResolver::isResolved($interaction) ? $interaction : null;
    }

    public function save(Interaction $interaction): void
    {
        $this->store($interaction);
    }
}
