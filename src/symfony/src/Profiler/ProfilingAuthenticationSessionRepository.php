<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function implode;
use Symfony\Component\Uid\Uuid;
use const DATE_ATOM;

/**
 * What the session of the request had proven (OIDC Core §2, RFC 8176 §2): the methods, the class they
 * satisfy (decision 0010), when the user last authenticated, and whether the session has ended since.
 * The class is computed from the proofs and read from nowhere else, exactly as the tokens compute it.
 *
 * Who the user is stays out: a session is named by its identifier, which is the "sid" the tokens carry
 * anyway, and by nothing else (decision 0011).
 */
final readonly class ProfilingAuthenticationSessionRepository implements AuthenticationSessionRepositoryInterface
{
    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
        private OpProfile $profile,
    ) {
    }

    public function find(Uuid $id): ?AuthenticationSession
    {
        $session = $this->sessions->find($id);
        if ($session !== null) {
            $this->profile->record(self::observe($session));
        }

        return $session;
    }

    public function findActiveByUser(User $user, DateTimeImmutable $now): array
    {
        return $this->sessions->findActiveByUser($user, $now);
    }

    public function save(AuthenticationSession $session): void
    {
        $this->sessions->save($session);
        $this->profile->record(self::observe($session));
    }

    private static function observe(AuthenticationSession $session): Observation
    {
        return new Observation('Session', 'Session', [
            'sid' => $session->id->toRfc4122(),
            'auth_time' => $session->authenticatedAt()->format(DATE_ATOM),
            'amr' => implode(' ', $session->methodReferences()),
            'acr' => $session->authenticationContextClass()->value,
            'expires at' => $session->expiresAt->format(DATE_ATOM),
            'ended' => $session->hasEnded() ? 'yes' : 'no',
        ]);
    }
}
