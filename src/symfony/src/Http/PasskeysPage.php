<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the passkeys of a user (architecture §5.2), rendered by the controller that shows it and by
 * the ones that come back to it with what went wrong.
 */
final readonly class PasskeysPage
{
    public function __construct(
        private CredentialRepositoryInterface $credentials,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $error a code the template translates
     */
    public function render(User $user, ?string $error = null, int $status = Response::HTTP_OK): Response
    {
        return $this->pages->render(
            'account/passkeys.html.twig',
            [
                'user' => $user,
                'passkeys' => $this->credentials->findByUser($user, PasskeyCredential::class),
                'error' => $error,
            ],
            $status,
        );
    }
}
