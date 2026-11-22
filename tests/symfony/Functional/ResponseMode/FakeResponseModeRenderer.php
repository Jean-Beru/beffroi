<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\ResponseMode;

use App\Http\ResponseMode\AuthorizationResponseRendererInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Symfony\Component\HttpFoundation\Response;

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
