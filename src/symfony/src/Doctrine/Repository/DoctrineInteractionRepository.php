<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Port\InteractionRepositoryInterface;

/**
 * Interactions in heidi_interaction (architecture §4.3). An interaction whose client is no longer
 * registered is not found: there is nothing to resume it for.
 *
 * @extends DoctrineRepository<Interaction>
 */
final readonly class DoctrineInteractionRepository extends DoctrineRepository implements InteractionRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Interaction::class);
    }

    public function find(string $id): ?Interaction
    {
        $interaction = $this->repository()
            ->findOneBy([
                'id' => $id,
            ]);

        return $interaction !== null && ClientResolver::isResolved($interaction) ? $interaction : null;
    }

    public function save(Interaction $interaction): void
    {
        $this->store($interaction);
    }
}
