<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;

/**
 * Interactions in beffroi_interaction (architecture §4.3). An interaction of a client no longer registered
 * is not found.
 *
 * @extends DoctrineRepository<Interaction>
 */
final readonly class DoctrineInteractionRepository extends DoctrineRepository implements InteractionRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, Interaction::class);
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
