<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Message\CheckThePasswordAgainstTheBreaches;
use Beffroi\Core\Application\Credential\BreachedPasswordLookup;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Asks a list of compromised passwords about the password that just signed somebody in, and marks the
 * credential with what it said (issue #552). On the lane, because a login keeps no third party on it.
 *
 * A credential that is gone by the time this runs is nothing to mark, and the message is done: a password
 * replaced between the login and the lookup is not the password this was asked about, and the login that
 * posed the new one will be looked up on its own. A password replaced in between is also why the digest is
 * not compared with the hash here: the mark is the lane's answer about the password of that moment, and
 * changePassword() drops it.
 *
 * What the list could not answer is not caught: the exception of the port leaves this handler, the
 * transport tries it again on its patience, and the credential stays due either way.
 */
#[AsMessageHandler]
final readonly class CheckThePasswordAgainstTheBreachesHandler
{
    public function __construct(
        private CredentialRepositoryInterface $credentials,
        private BreachedPasswordLookup $lookup,
    ) {
    }

    public function __invoke(CheckThePasswordAgainstTheBreaches $command): void
    {
        $credential = $this->credentials->find($command->credential);
        if (! $credential instanceof PasswordCredential) {
            return;
        }
        $this->lookup->lookUp($credential, new PasswordDigest($command->digest));
    }
}
