<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use function array_map;
use DateTimeImmutable;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Authentication\SessionOpener;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Domain\Event\PasskeyUsed;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use LogicException;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Opens the session of the core after a login of the firewall, with a password or with a passkey, through
 * the SessionOpener of the core, and binds the browser to it (architecture §3.2, §5.4). A re-login records
 * its proofs on the session the browser holds rather than opening another; a browser bound to someone
 * else's session ends it first. The proofs are copied into the token of Symfony (symfony/symfony#66064).
 */
final readonly class LoginSuccessListener
{
    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthenticationSessionRepositoryInterface $sessions,
        private CredentialRepositoryInterface $credentials,
        private SessionOpener $opener,
        private SessionTerminator $terminator,
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (! $user instanceof SecurityUser) {
            return;
        }
        $passport = $event->getPassport();
        $methods = self::methods($passport);
        $request = $event->getRequest();
        $context = $this->contexts->fromRequest($request);
        $now = $context->receivedAt;
        $tenant = $this->tenants->provide();

        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session !== null && $session->user->id->equals($user->id)) {
            foreach ($methods as $method) {
                $session->recordProof($method, $context);
            }
            $this->sessions->save($session);
        } else {
            if ($session !== null) {
                $this->terminator->end($session, SessionEnd::User, $context);
            }
            $session = $this->opener->open($tenant, $user->user(), $methods, $context);
        }

        $this->recordUse($passport, $user, $now, $context);

        $this->browser->bind($request->getSession(), $session);
        $event->getAuthenticatedToken()
            ->setAuthenticationProofs(array_map(
                static fn (DateTimeImmutable $provenAt): int => $provenAt->getTimestamp(),
                $session->proofs->entries,
            ));
    }

    /**
     * What the passport proved, as the core names it (RFC 8176 §2): "pwd" for a password, what the flags
     * of the assertion say for a passkey (PasskeyCredential::methods()). A firewall that authenticates
     * another way is refused loudly rather than recorded wrongly.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    private static function methods(Passport $passport): array
    {
        if ($passport->hasBadge(PasswordCredentials::class)) {
            return [AuthenticationMethod::password()];
        }
        $passkey = $passport->getBadge(PasskeyCredentials::class);
        if ($passkey instanceof PasskeyCredentials) {
            return $passkey->assertion->credential->methods($passkey->assertion->authenticatorData);
        }

        throw new LogicException(sprintf('The firewall authenticated a user of the bundle without a method the bundle knows: no "%s" nor "%s" badge on the passport.', PasswordCredentials::class, PasskeyCredentials::class));
    }

    /**
     * The credential that proved the login is dated; a passkey also records its sign count and its backup
     * state (WebAuthn Level 3 §7.2, step 26) and is announced, a count that did not grow told, not refused.
     */
    private function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): void
    {
        $passkey = $passport->getBadge(PasskeyCredentials::class);
        if ($passkey instanceof PasskeyCredentials) {
            $credential = $passkey->assertion->credential;
            $signCountRegressed = $credential->signCountRegresses($passkey->assertion->authenticatorData);
            $credential->recordUse($passkey->assertion->authenticatorData, $now);
            $this->credentials->save($credential);
            $this->events->dispatch(new PasskeyUsed($credential, $now, $context, $signCountRegressed));

            return;
        }
        $credential = $user->passwordCredential();
        if ($credential !== null) {
            $credential->markUsed($now);
            $this->credentials->save($credential);
        }
    }
}
