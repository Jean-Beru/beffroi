<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use const DATE_ATOM;

/**
 * What the user has agreed to let this client obtain (architecture §4.3): the scopes of the consent the
 * request stood on, and the ones of the consent the request wrote. Between the scopes of the request and
 * the scopes of the tokens, this is what says why the two differ.
 */
final readonly class ProfilingConsentRepository implements ConsentRepositoryInterface
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private OpProfile $profile,
    ) {
    }

    public function findActive(User $user, Client $client): ?Consent
    {
        $consent = $this->consents->findActive($user, $client);
        if ($consent !== null) {
            $this->profile->record(self::observe($consent, 'found'));
        }

        return $consent;
    }

    public function save(Consent $consent): void
    {
        $this->consents->save($consent);
        $this->profile->record(self::observe($consent, 'granted'));
    }

    private static function observe(Consent $consent, string $state): Observation
    {
        return new Observation('Client', 'Consent', [
            'client_id' => $consent->clientId,
            'state' => $state,
            'scopes consented' => (string) $consent->scopes,
            'granted at' => $consent->grantedAt->format(DATE_ATOM),
        ]);
    }
}
