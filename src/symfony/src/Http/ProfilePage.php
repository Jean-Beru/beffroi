<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Http\Account\RecordedInformation;
use Beffroi\Core\Domain\Identity\User;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where a person consults what this provider holds about them (architecture §5.2): the account
 * itself, then what they told us, each thing with its label and its value. What is on it is what the
 * record holds, read at every visit, never a copy this page keeps.
 */
final readonly class ProfilePage
{
    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        return $this->pages->render('account/profile.html.twig', [
            'user' => $user,
            'identity' => RecordedInformation::identityOf($user),
            'claims' => RecordedInformation::claimsOf($user),
        ]);
    }
}
