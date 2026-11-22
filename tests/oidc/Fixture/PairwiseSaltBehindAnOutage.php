<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Oidc\Port\PairwiseSaltInterface;

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
