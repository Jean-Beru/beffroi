<?php

declare(strict_types=1);

namespace App\Http;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use function is_array;
use function is_int;
use function is_string;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * The provisioning of a TOTP between the page that shows it and the code that confirms it (architecture
 * §5.2): kept in the HTTP session of the browser, for the user it was drawn for, sealed by the KMS of the
 * tenant like the secret will be once stored (§3.3), because a session store is a disk and the secret,
 * the URI that carries it and the backup codes exist in clear in memory only. One at a time per browser,
 * a new one replacing the old; read again on a wrong code, so that the QR code need not be scanned twice;
 * forgotten once a code confirmed it or once it expired. A KMS that does not answer forgets nothing: the
 * outage goes on as it came (KmsUnavailableException), the provisioning waits for the KMS to be back.
 */
final readonly class TotpProvisioningStore
{
    public const string KEY = 'beffroi.totp.provisioning';

    /**
     * Ten minutes to install an app and scan a code.
     */
    public const string LIFETIME = 'PT10M';

    public function __construct(
        private TotpProvisioningSealer $sealer,
    ) {
    }

    public function store(SessionInterface $session, User $user, TotpProvisioning $provisioning, DateTimeImmutable $now): void
    {
        $session->set(self::KEY, [
            'user' => $user->id->toRfc4122(),
            'expires_at' => $now->add(new DateInterval(self::LIFETIME))->getTimestamp(),
            'sealed' => $this->sealer->seal($user, $provisioning),
        ]);
    }

    /**
     * The provisioning drawn for this user and still valid, or null; one drawn for someone else, one that
     * expired and one the KMS refuses as foreign or invalid are forgotten and null.
     *
     * @throws KmsUnavailableException when the KMS of the tenant does not answer; the provisioning is kept
     */
    public function provisioning(SessionInterface $session, User $user, DateTimeImmutable $now): ?TotpProvisioning
    {
        $stored = $session->get(self::KEY);
        if (! is_array($stored)) {
            return null;
        }
        $expiresAt = $stored['expires_at'] ?? null;
        $sealed = $stored['sealed'] ?? null;
        if (($stored['user'] ?? null) !== $user->id->toRfc4122() || ! is_int($expiresAt) || $now->getTimestamp() >= $expiresAt || ! is_string($sealed)) {
            $session->remove(self::KEY);

            return null;
        }
        try {
            return $this->sealer->unseal($user, $sealed);
        } catch (RuntimeException|InvalidArgumentException) {
            $session->remove(self::KEY);

            return null;
        }
    }

    public function forget(SessionInterface $session): void
    {
        $session->remove(self::KEY);
    }
}
