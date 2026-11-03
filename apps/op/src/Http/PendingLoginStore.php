<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Core\Domain\Session\PendingLogin;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The login held between its two steps (architecture §5.4), in the HTTP session of the browser that
 * typed the password: one at a time, the newer replacing the older, forgotten once a code completed it.
 * Nothing of it is a secret: an identifier, the methods proven and two instants.
 *
 * **It judges nothing of what it holds** (issue #130): whether a held login has run out of time is a
 * refusal of the second step, which the core pronounces and announces for both paths
 * (PendingLoginVerification), where a store that forgot an expired login by itself made the firewall
 * answer a browser that was late exactly as it answered one that had held nothing.
 */
final readonly class PendingLoginStore
{
    public const string KEY = '_beffroi_pending_login';

    public function hold(SessionInterface $session, PendingLogin $login): void
    {
        $session->set(self::KEY, $login);
    }

    /**
     * The login this browser holds, whatever state it is in, or null when it holds none.
     */
    public function held(SessionInterface $session): ?PendingLogin
    {
        $login = $session->get(self::KEY);

        return $login instanceof PendingLogin ? $login : null;
    }

    public function forget(SessionInterface $session): void
    {
        $session->remove(self::KEY);
    }
}
