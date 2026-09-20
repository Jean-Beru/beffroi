<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use function array_any;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use LogicException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * What the logins of the firewall prove, as the core names it (RFC 8176 §2), in one place: what a given
 * passport proved, for the session the listener opens, and everything a login here may prove, for the
 * discovery and the step-up (decision 0010). Neither is an enumeration: both are read from the logins
 * that are tagged (ProvingLoginInterface), so that what the provider announces is what is wired, and a
 * login added to the firewall is a class tagged and nothing edited.
 */
final readonly class PassportProofs implements ProvableMethodsInterface
{
    /**
     * @param iterable<ProvingLoginInterface> $logins the logins of the firewall, at least one
     */
    public function __construct(
        private iterable $logins,
    ) {
    }

    /**
     * The first login that recognises the passport answers; they are mutually exclusive, a passport
     * carrying the badge of one login only. A firewall that authenticates another way is refused loudly
     * rather than recorded wrongly.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function methods(Passport $passport): array
    {
        foreach ($this->logins as $login) {
            $methods = $login->proofs($passport);
            if ($methods !== null) {
                return $methods;
            }
        }

        throw new LogicException('The firewall authenticated a user of the bundle with a login none of the tagged ones recognises: the passport carries the badge of no login of the bundle.');
    }

    /**
     * Every method the wired logins prove, each once, in the order they are tagged.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function provableMethods(): array
    {
        $methods = [];
        foreach ($this->logins as $login) {
            foreach ($login->everyProvableMethod() as $method) {
                if (! array_any($methods, static fn (AuthenticationMethod $known): bool => $known->equals($method))) {
                    $methods[] = $method;
                }
            }
        }
        if ($methods === []) {
            throw new LogicException('The firewall of the interaction pages offers at least one login.');
        }

        return $methods;
    }
}
