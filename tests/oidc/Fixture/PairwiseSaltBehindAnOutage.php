<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Oidc\Port\PairwiseSaltInterface;

/**
 * A salt sealed under a KMS a test takes down and brings back: while it is down, opening the salt fails as a KMS
 * that does not answer fails (KmsUnavailableException); while it is up, the salt is the one of the salts it was
 * given. Never leaves the test suite.
 */
final class PairwiseSaltBehindAnOutage implements PairwiseSaltInterface
{
    public const string WORDS_OF_THE_KMS = 'The KMS did not answer to open the pairwise salt.';

    public bool $down = false;

    public function __construct(
        private readonly PairwiseSaltInterface $salts = new FixedPairwiseSalt(),
    ) {
    }

    public function saltOf(Tenant $tenant): string
    {
        if ($this->down) {
            throw new KmsUnavailableException(self::WORDS_OF_THE_KMS);
        }

        return $this->salts->saltOf($tenant);
    }
}
