<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Identity\User;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where a person replaces their own password (architecture §5.2): when it was last written, the
 * form that replaces it, and what the form was refused.
 *
 * **It says when the password was last written**, which is what a page like this has to show: nothing
 * visible changes when a password does, so the date is the answer a person reads after they changed it,
 * and the one thing they can check against what they remember.
 *
 * **A person who holds no password reads that they hold none.** Somebody who signs in by passkey alone
 * has nothing to replace here, and this page does not offer to set a first one: posing a password is an
 * enrolment, and an enrolment proves something first.
 */
final readonly class PasswordPage
{
    public function __construct(
        private ActiveCredentials $credentials,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $refusal a code the template translates, read once out of the session the
     *                             redirection crossed (issue #481)
     */
    public function render(User $user, ?string $refusal = null): Response
    {
        return $this->pages->render('account/password.html.twig', [
            'user' => $user,
            'password' => $this->of($user),
            'refusal' => $refusal,
            'minimum' => PlainPassword::MINIMUM_LENGTH,
        ]);
    }

    /**
     * The password this person holds, null for somebody who signs in by another means.
     */
    public function of(User $user): ?PasswordCredential
    {
        return $this->credentials->of($user, PasswordCredential::class)[0] ?? null;
    }
}
