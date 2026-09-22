<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * The response modes an integration wired: the default alone, as spike 1 had, the default and the posted
 * form, as the bundle wired from spike 4, or the four the bundle wires since issue #163, the two
 * deliveries of a signed document beside them.
 */
final readonly class ServedModes implements ServedResponseModesInterface
{
    /**
     * @param non-empty-list<ResponseMode> $modes
     */
    private function __construct(
        private array $modes,
    ) {
    }

    public static function queryOnly(): self
    {
        return new self([ResponseMode::Query]);
    }

    public static function queryAndFormPost(): self
    {
        return new self([ResponseMode::Query, ResponseMode::FormPost]);
    }

    /**
     * JARM §2.1: the two deliveries of a signed answer, beside the two unsigned ones.
     */
    public static function signedToo(): self
    {
        return new self([ResponseMode::Query, ResponseMode::FormPost, ResponseMode::QueryJwt, ResponseMode::FormPostJwt]);
    }

    public function servedResponseModes(): array
    {
        return $this->modes;
    }
}
