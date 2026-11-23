<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Port\PasskeyUsesInterface;
use Closure;
use DateTimeImmutable;
use Webauthn\AuthenticatorData;

/**
 * Another request runs to its end between the checks of this one and its write, as it does on another worker.
 */
final class PasskeyUsesRacedByAnotherRequest implements PasskeyUsesInterface
{
    /**
     * @var (Closure(): void)|null
     */
    public ?Closure $anotherRequest = null;

    public function __construct(
        private readonly PasskeyUsesInterface $uses,
    ) {
    }

    public function recordUse(PasskeyCredential $credential, AuthenticatorData $data, DateTimeImmutable $now): bool
    {
        $request = $this->anotherRequest;
        $this->anotherRequest = null;
        if ($request !== null) {
            $request();
        }

        return $this->uses->recordUse($credential, $data, $now);
    }
}
