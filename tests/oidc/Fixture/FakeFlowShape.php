<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Flow\FlowShapeInterface;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

final readonly class FakeFlowShape implements FlowShapeInterface
{
    /**
     * @param list<GrantTypeName> $drawn
     * @param non-empty-string    $hop
     */
    public function __construct(
        private array $drawn,
        private string $hop,
    ) {
    }

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $this->drawn;
    }

    public function hops(): array
    {
        return [new Hop(Actor::Client, Actor::Provider, $this->hop, 'RFC 6749 §3.2')];
    }
}
