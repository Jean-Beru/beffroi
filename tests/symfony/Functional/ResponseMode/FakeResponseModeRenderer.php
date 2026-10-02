<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\ResponseMode;

use Beffroi\Bundle\Http\ResponseMode\AuthorizationResponseRendererInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Symfony\Component\HttpFoundation\Response;

/**
 * A way of answering that answers to the name a test gives it and delivers the name it answered in, so a
 * test of the wiring can tell which of them was asked. The three kinds below are the three declarations a
 * renderer can make: it delivers, it delivers a document the tenant signs (JARM §2), and it is the one the
 * alias resolves to (JARM §2.1).
 */
class FakeResponseModeRenderer implements AuthorizationResponseRendererInterface
{
    /**
     * @param non-empty-string $mode
     */
    public function __construct(
        private readonly string $mode,
    ) {
    }

    public function mode(): string
    {
        return $this->mode;
    }

    public function render(AuthorizationAnswer $answer): Response
    {
        return new Response($this->mode);
    }
}
