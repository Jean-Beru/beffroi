<?php

declare(strict_types=1);

namespace App\Http\ResponseMode;

use Beffroi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Symfony\Component\HttpFoundation\Response;

/**
 * JARM §2.1: the answer gathered in a document the tenant signs, carried in the query of the redirect
 * URI as one "response" parameter. It is what "response_mode=jwt" resolves to for the "code" response
 * type, the only one this provider serves (decision 0006). The document is minted by the module; the
 * delivery is the ordinary query mode, so a signed answer travels exactly as an unsigned one does.
 */
final readonly class SignedQueryResponseRenderer implements AnswersTheJwtAliasInterface
{
    public function __construct(
        private ResponseDocumentIssuer $documents,
        private QueryResponseRenderer $delivery,
    ) {
    }

    public function mode(): string
    {
        return 'query.jwt';
    }

    public function render(AuthorizationAnswer $answer): Response
    {
        return $this->delivery->render($answer->signedWith($this->documents->issue($answer)));
    }
}
