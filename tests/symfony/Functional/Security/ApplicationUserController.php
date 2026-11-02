<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Security;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

/**
 * A page of the host application behind its own firewall (issue #282): it answers the identifier of whoever that
 * firewall signed in, which is the subject the provider gave the application for them, and 401 to nobody.
 */
final readonly class ApplicationUserController
{
    public function __invoke(#[CurrentUser] ?UserInterface $user): Response
    {
        return $user === null ? new Response('', Response::HTTP_UNAUTHORIZED) : new Response($user->getUserIdentifier());
    }
}
