<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\PersonalData;

use function count;
use Doctrine\DBAL\Connection;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Domain\Event\TenantDataKeysDestroyed;
use Heidi\Core\Domain\Tenant\Tenant;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;

/**
 * The one thing that erases a data key (decisions 0011 and 0018).
 *
 * A retired key stays in the store and goes on opening what it sealed, which is why nothing in the
 * ordinary life of a tenant removes a row: a rotation mints a key beside the ones that are there, and a
 * rewrap changes how a key is protected and not the key. **Only the deliberate removal of a tenant erases
 * one**, and what it makes of that tenant's sealed columns is that nothing reads them again, ever, by
 * anybody, which is the erasure this provider promises.
 *
 * It is a statement of its own and not a method of the router: the router is what the encryption path
 * sees, and the encryption path has no business holding something that erases.
 *
 * The rows are matched on the prefix of their scope, which is the slug of the tenant followed by the
 * separator: that is the only place a tenant is written in this table, the store knowing nothing of one
 * (decision 0018). A slug is one to sixty-three lowercase letters, digits or hyphens, so it carries
 * nothing a `LIKE` would read as a pattern.
 */
final readonly class TenantDataKeyDestruction
{
    public function __construct(
        private Connection $connection,
        private TenantDataKeys $keys,
        private EventDispatcherInterface $events,
        private RequestContextFactory $contexts,
        private string $table = TenantDataKeyStores::TABLE,
    ) {
    }

    /**
     * @param string $askedBy what the audit trail says asked for it, a command name
     *
     * @return int how many keys were erased, which is zero for a tenant that had sealed nothing
     */
    public function destroy(Tenant $tenant, string $askedBy): int
    {
        // Counted before, because afterwards there is nothing left to count, which is the whole point.
        $scopes = count($this->keys->of($tenant));
        $erased = (int) $this->connection->executeStatement(
            sprintf('DELETE FROM %s WHERE scope LIKE :prefix', $this->table),
            [
                'prefix' => $tenant->slug . TenantScopedEncrypter::SEPARATOR . '%',
            ],
        );

        $context = $this->contexts->fromConsole($askedBy);
        $this->events->dispatch(new TenantDataKeysDestroyed($tenant, $erased, $scopes, $context->receivedAt, $context));

        return $erased;
    }
}
