<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Account;

use function array_map;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * What applications hold of a person, read from the stores that hold it (issue #451). The page of one
 * application asks for one, the console asks for every one of them, and the question is answered in one
 * place so that the two say the same thing of the same person at the same instant.
 */
final readonly class ApplicationHoldings
{
    public function __construct(
        private RefreshTokensOfAConsentInterface $renewals,
        private BackchannelAuthenticationRecordRepositoryInterface $backchannel,
        private ClockInterface $clock,
    ) {
    }

    public function of(User $user, Consent $consent): ApplicationHolding
    {
        $now = $this->clock->now();

        return $this->holding($consent, $this->backchannel->awaitingAnAnswerBy($user, $now), $now);
    }

    /**
     * What waits for this person is asked for once, whatever the number of applications: it is a reading of
     * them and not of one application, and the holding of each keeps the records that name it.
     *
     * @param list<Consent> $consents
     *
     * @return list<ApplicationHolding> in the order the consents were given
     */
    public function ofEach(User $user, array $consents): array
    {
        $now = $this->clock->now();
        $awaiting = $this->backchannel->awaitingAnAnswerBy($user, $now);

        return array_map(
            fn (Consent $consent): ApplicationHolding => $this->holding($consent, $awaiting, $now),
            $consents,
        );
    }

    /**
     * @param list<BackchannelAuthenticationRecord> $awaiting
     */
    private function holding(Consent $consent, array $awaiting, DateTimeImmutable $now): ApplicationHolding
    {
        return ApplicationHolding::of($consent, $this->renewals->ofConsent($consent), $awaiting, $now);
    }
}
