<?php

declare(strict_types=1);

namespace App\Http\ResponseMode;

use Beffroi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Symfony\Component\HttpFoundation\Response;

/**
 * JARM §2.1: the answer gathered in a document the tenant signs, posted by the page of Form Post
 * Response Mode §2 as one "response" field. The document is minted by the module; the delivery is the
 * ordinary form post mode, so that the page, its policy and its script are written once.
 */
final readonly class SignedFormPostResponseRenderer implements SignsTheAnswerInterface
{
    public function __construct(
        private ResponseDocumentIssuer $documents,
        private FormPostResponseRenderer $delivery,
    ) {
    }

    public function mode(): string
    {
        return 'form_post.jwt';
    }

    public function render(AuthorizationAnswer $answer): Response
    {
        return $this->delivery->render($answer->signedWith($this->documents->issue($answer)));
    }
}
