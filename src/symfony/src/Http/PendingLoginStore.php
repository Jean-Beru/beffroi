<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\PendingLogin;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The login held between its two steps (architecture §5.4), in the HTTP session of the browser that
 * typed the password: one at a time, the newer replacing the older, forgotten once a code completed it
 * or once it expired. Nothing of it is a secret: an identifier, the methods proven and two instants.
 */
final readonly class PendingLoginStore
{
    public const string KEY = '_beffroi_pending_login';

    public function hold(SessionInterface $session, PendingLogin $login): void
    {
        $session->set(self::KEY, $login);
    }

    /**
     * The login still pending, or null; an expired one is forgotten here.
     */
    public function pending(SessionInterface $session, DateTimeImmutable $now): ?PendingLogin
    {
        $login = $session->get(self::KEY);
        if (! $login instanceof PendingLogin) {
            return null;
        }
        if ($login->isExpired($now)) {
            $session->remove(self::KEY);

            return null;
        }

        return $login;
    }

    public function forget(SessionInterface $session): void
    {
        $session->remove(self::KEY);
    }
}
