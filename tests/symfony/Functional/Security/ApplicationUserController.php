<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

final readonly class ApplicationUserController
{
    public function __invoke(#[CurrentUser] ?UserInterface $user): Response
    {
        return $user === null ? new Response('', Response::HTTP_UNAUTHORIZED) : new Response($user->getUserIdentifier());
    }
}
