<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Port\CanPageActiveSubscriptionsInterface;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The browsers of a user this provider may push to, in beffroi_push_subscription (architecture §3.1). A
 * browser is recognised by the digest of its endpoint, as the unique constraint of the table is: an
 * endpoint is as long as its push service decided, and comparing a digest compares the whole of it.
 *
 * @extends DoctrineRepository<PushSubscription>
 */
final readonly class DoctrinePushSubscriptionRepository extends DoctrineRepository implements
    CanPageActiveSubscriptionsInterface,
    PushSubscriptionRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, PushSubscription::class);
    }

    /**
     * A person holds a handful of these, so the page is taken of what the list above answers.
     *
     * @return Listing<PushSubscription>
     */
    public function pageOfActiveSubscriptions(User $user, Pagination $pagination): Listing
    {
        return Listing::of($this->findActiveByUser($user), $pagination);
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
