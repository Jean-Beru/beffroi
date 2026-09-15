<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function array_filter;
use function array_slice;
use function array_values;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use function in_array;
use function is_array;
use function is_string;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * What the HTTP session of a browser holds of the provider: the AuthenticationSession of the core it is
 * bound to, and the interactions it began. The core owns the session record and the decisions built on
 * it; the integration owns the cookie (architecture §3.2), and this is the cookie side.
 *
 * An interaction is resumed only by the browser that began it (architecture §4.3): its identifier travels
 * in the URL of the login and consent pages, and the HTTP session confirms it, which closes a login on
 * someone else's interaction and the replay of an identifier read in a log. A browser may have several
 * interactions in flight, one per tab; the list is bounded and the oldest is forgotten first.
 *
 * The session bound here is the one the login of the firewall (#15) establishes; until then, bind() is
 * what a test calls.
 */
final readonly class BrowserSession
{
    public const string AUTHENTICATION_SESSION_KEY = '_heidi_session';

    public const string INTERACTIONS_KEY = '_heidi_interactions';

    public const int MAX_PENDING_INTERACTIONS = 8;

    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
        private InteractionRepositoryInterface $interactions,
        private ClockInterface $clock,
    ) {
    }

    /**
     * The authentication session the browser is bound to, when it names one of this tenant that is still
     * active. A binding to a session that ended or expired is dropped: the browser is not authenticated.
     */
    public function authenticationSession(Request $request, Tenant $tenant): ?AuthenticationSession
    {
        if (! $request->hasPreviousSession()) {
            return null;
        }
        $httpSession = $request->getSession();
        $id = $httpSession->get(self::AUTHENTICATION_SESSION_KEY);
        if (! is_string($id) || ! Uuid::isValid($id)) {
            return null;
        }
        $session = $this->sessions->find(Uuid::fromString($id));
        if ($session === null || ! $session->tenant->equals($tenant) || ! $session->isActive($this->clock->now())) {
            $httpSession->remove(self::AUTHENTICATION_SESSION_KEY);

            return null;
        }

        return $session;
    }

    /**
     * Binds the browser to a freshly established session. The HTTP session identifier is regenerated so
     * that an identifier fixed before the login opens nothing after it.
     */
    public function bind(SessionInterface $httpSession, AuthenticationSession $session): void
    {
        $httpSession->migrate(true);
        $httpSession->set(self::AUTHENTICATION_SESSION_KEY, $session->id->toRfc4122());
    }

    /**
     * Forgets everything: the session binding and the interactions in flight. The HTTP session is
     * invalidated, so that the cookie the browser holds names nothing any more.
     */
    public function unbind(SessionInterface $httpSession): void
    {
        $httpSession->invalidate();
    }

    /**
     * Remembers that this browser began the interaction.
     */
    public function begin(SessionInterface $httpSession, Interaction $interaction): void
    {
        $ids = self::pendingIds($httpSession);
        if (! in_array($interaction->id, $ids, true)) {
            $ids[] = $interaction->id;
        }
        $httpSession->set(self::INTERACTIONS_KEY, array_slice($ids, -self::MAX_PENDING_INTERACTIONS));
    }

    /**
     * The interaction named by a page of this browser, when it exists, serves this tenant and was begun
     * by this browser; null in every other case, without telling which.
     */
    public function pending(Request $request, Tenant $tenant, ?string $id): ?Interaction
    {
        if ($id === null || $id === '' || ! $request->hasPreviousSession()) {
            return null;
        }
        if (! in_array($id, self::pendingIds($request->getSession()), true)) {
            return null;
        }
        $interaction = $this->interactions->find($id);
        if ($interaction === null || ! $interaction->tenant->equals($tenant)) {
            return null;
        }

        return $interaction;
    }

    /**
     * The interaction reached its outcome: granted, denied, failed or expired, it is not pending any more.
     */
    public function forget(SessionInterface $httpSession, Interaction $interaction): void
    {
        $ids = array_values(array_filter(self::pendingIds($httpSession), static fn (string $id): bool => $id !== $interaction->id));
        if ($ids === []) {
            $httpSession->remove(self::INTERACTIONS_KEY);

            return;
        }
        $httpSession->set(self::INTERACTIONS_KEY, $ids);
    }

    /**
     * @return list<string>
     */
    private static function pendingIds(SessionInterface $httpSession): array
    {
        $ids = $httpSession->get(self::INTERACTIONS_KEY);
        if (! is_array($ids)) {
            return [];
        }
        $strings = [];
        foreach ($ids as $id) {
            if (is_string($id)) {
                $strings[] = $id;
            }
        }

        return $strings;
    }
}
