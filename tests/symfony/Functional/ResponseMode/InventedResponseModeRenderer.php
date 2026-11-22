<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\ResponseMode;

use App\Http\ResponseMode\AuthorizationResponseRendererInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use function http_build_query;
use Symfony\Component\HttpFoundation\Response;

final readonly class InventedResponseModeRenderer implements AuthorizationResponseRendererInterface
{
    public const string MODE = 'invented';

    public const string CONTENT_TYPE = 'application/x-invented-response';

    public function mode(): string
    {
        return self::MODE;
    }

    public function render(AuthorizationAnswer $answer): Response
    {
        return new Response(http_build_query($answer->parameters), Response::HTTP_OK, [
            'Content-Type' => self::CONTENT_TYPE,
        ]);
    }
}
