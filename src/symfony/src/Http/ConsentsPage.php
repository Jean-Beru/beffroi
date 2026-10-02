<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of what a user has agreed to (architecture §5.2): the clients that may obtain something about
 * them, what each was granted and when. What is in force is what the store answers, never a list this
 * page keeps.
 */
final readonly class ConsentsPage
{
    public function __construct(
        private ActiveConsentsInterface $consents,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        return $this->pages->render('account/consents.html.twig', [
            'user' => $user,
            'consents' => $this->consents->activeOf($user),
        ]);
    }
}
