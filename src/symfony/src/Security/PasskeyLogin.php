<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\PasskeyUsed;
use Beffroi\Bundle\Controller\PasskeyLoginController;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Throwable;

/**
 * The passkey login of the firewall (architecture §5.4): what the flags of the assertion say
 * (PasskeyCredential::methods(), WebAuthn Level 3 §6.1), read from the badge the authenticator put on
 * the passport after the ceremony.
 */
final readonly class PasskeyLogin implements AnnouncesItsRefusalInterface, DatesItsCredentialInterface, OfferedLoginInterface
{
    public function kind(): string
    {
        return 'passkey';
    }

    public function __construct(
        private CredentialRepositoryInterface $credentials,
        private EventDispatcherInterface $events,
    ) {
    }

    public function proofs(Passport $passport): ?array
    {
        $badge = $passport->getBadge(PasskeyCredentials::class);
        if (! $badge instanceof PasskeyCredentials) {
            return null;
        }

        return $badge->assertion->credential->methods($badge->assertion->authenticatorData);
    }

    /**
     * The flags of an assertion all set at once (decision 0010, architecture §4.8): the key as its backup
     * eligibility says, "swk" for a synced passkey and "hwk" for one bound to its authenticator, "user",
     * the presence §7.2 requires of every assertion, and "mfa", which the authenticator decides at each
     * assertion under userVerification "preferred" and which no single passkey promises ahead
     * (PasskeyCredential::provableMethods()). What this login can reach for a given user is that one,
     * credential by credential; what it can reach at all is this.
     */
    public function everyProvableMethod(): array
    {
        return [
            new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY),
            new AuthenticationMethod(AuthenticationMethod::SOFTWARE_KEY),
            new AuthenticationMethod(AuthenticationMethod::USER_PRESENCE),
            new AuthenticationMethod(AuthenticationMethod::MULTIPLE_FACTORS),
        ];
    }

    /**
     * WebAuthn Level 3 §7.2, step 26: the key is dated with its sign count and its backup state, and the
     * use is announced; a count that did not grow was refused before (PasskeyLoginAuthenticator).
     */
    public function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): bool
    {
        $badge = $passport->getBadge(PasskeyCredentials::class);
        if (! $badge instanceof PasskeyCredentials) {
            return false;
        }
        $credential = $badge->assertion->credential;
        $credential->recordUse($badge->assertion->authenticatorData, $now);
        $this->credentials->save($credential);
        $this->events->dispatch(new PasskeyUsed($credential, $now, $context));

        return true;
    }

    public function route(): string
    {
        return PasskeyLoginController::ROUTE;
    }

    /**
     * What the authenticator of the bundle refused, with the reason it gave, or the account the checker
     * refused after the signature; nothing was typed, so the identifier is null. A request without a
     * pending ceremony, without an assertion or without its form token is not an attempt on an account.
     */
    public function refusal(AuthenticationException $exception, ?Passport $passport): ?LoginFailure
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof PasskeyLoginException) {
                return new LoginFailure($cause->method, $cause->reason, null, $cause->user);
            }
        }
        $badge = $passport?->getBadge(PasskeyCredentials::class);
        if (! $badge instanceof PasskeyCredentials || AuthenticationFailureCause::of($exception) !== AuthenticationFailureReason::DisabledUser) {
            return null;
        }
        $credential = $badge->assertion->credential;

        return new LoginFailure(
            $credential->methods($badge->assertion->authenticatorData)[0],
            AuthenticationFailureReason::DisabledUser,
            null,
            $credential->user,
        );
    }
}
