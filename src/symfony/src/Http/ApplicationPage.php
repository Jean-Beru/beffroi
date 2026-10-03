<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Http\Account\ApplicationHolding;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of one application (issue #451, architecture §4.3, §5.2): what this person agreed to let it
 * obtain and when, what of it the application can still renew at this instant, and what it has asked that
 * is waiting for an answer of theirs. The button that takes it back is the one of the list, and what it
 * revokes is the consent and everything issued under it, in one act (ConsentRevocation).
 */
final readonly class ApplicationPage
{
    public function __construct(
        private RefreshTokensOfAConsentInterface $renewals,
        private BackchannelAuthenticationRecordRepositoryInterface $backchannel,
        private ClockInterface $clock,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user, Consent $consent): Response
    {
        $now = $this->clock->now();

        return $this->pages->render('account/application.html.twig', [
            'user' => $user,
            'holding' => ApplicationHolding::of(
                $consent,
                $this->renewals->ofConsent($consent),
                $this->backchannel->awaitingAnAnswerBy($user, $now),
                $now,
            ),
        ]);
    }
}
