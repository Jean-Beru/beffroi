<?php

declare(strict_types=1);

namespace App\Profiler;

use function array_map;
use App\Doctrine\TenantNotSynchronizedException;
use App\Doctrine\TenantProvider;
use Beffroi\Oidc\Application\Discovery\DiscoveryHandler;
use function implode;
use function is_array;
use function is_bool;
use function is_scalar;
use LogicException;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * What this provider serves, for the tenant the request was made against: the discovery document itself
 * (OIDC Discovery §4), member by member. It is read from the handler that answers `/.well-known`, so the
 * panel announces what the provider announces, which is derived from what is wired and from nothing kept
 * in parallel (issue #98): a grant, a client authentication method, a response mode, an algorithm or a
 * logout channel that is wired shows up here for having been wired, and one that is not cannot appear.
 *
 * Built once the response is ready, and only for a request that reached an endpoint of the provider:
 * this is a page of a developer, not a cost every request of the application pays.
 */
#[AsEventListener(event: KernelEvents::RESPONSE, priority: self::PRIORITY)]
final readonly class ProviderCapabilitiesListener
{
    /**
     * Above the profiler, which collects at -100.
     */
    public const int PRIORITY = 0;

    public function __construct(
        private OpProfile $profile,
        private TenantProvider $tenants,
        private DiscoveryHandler $discovery,
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        if (! $event->isMainRequest() || ! $this->profile->hasTouchedTheProvider()) {
            return;
        }
        try {
            $metadata = $this->discovery->handle($this->tenants->provide())->toArray();
        } catch (LogicException|TenantNotSynchronizedException $exception) {
            $this->profile->record(new Observation('Provider', 'Provider', [
                'the document cannot be built' => $exception->getMessage(),
            ]));

            return;
        }
        $entries = [];
        foreach ($metadata as $member => $value) {
            $entries[$member] = self::written($value);
        }
        $this->profile->record(new Observation('Provider', 'What this provider serves', $entries));
    }

    private static function written(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'yes' : 'no';
        }
        if (is_array($value)) {
            return $value === [] ? 'none' : implode(' ', array_map(self::written(...), $value));
        }

        return is_scalar($value) ? (string) $value : 'a structure';
    }
}
