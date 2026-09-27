<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Identity\PushSubscription;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\PushSubscriptionRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The browsers of a user this provider may push to, in heidi_push_subscription (architecture §3.1). A
 * browser is recognised by the digest of its endpoint, as the unique constraint of the table is: an
 * endpoint is as long as its push service decided, and comparing a digest compares the whole of it.
 *
 * @extends DoctrineRepository<PushSubscription>
 */
final readonly class DoctrinePushSubscriptionRepository extends DoctrineRepository implements PushSubscriptionRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, PushSubscription::class);
    }

    public function findActiveByUser(User $user): array
    {
        return $this->repository()->findBy([
            'user' => $user,
            'revokedAt' => null,
        ], [
            'createdAt' => 'ASC',
        ]);
    }

    public function findByEndpoint(User $user, string $endpoint): ?PushSubscription
    {
        return $this->repository()->findOneBy([
            'user' => $user,
            'endpointHash' => PushSubscription::digestOf($endpoint),
        ]);
    }

    public function find(Uuid $id): ?PushSubscription
    {
        return $this->repository()->find($id);
    }

    public function save(PushSubscription $subscription): void
    {
        $this->store($subscription);
    }
}
