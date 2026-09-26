<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Symfony\Component\HttpFoundation\Response;

/**
 * One way of handing the answer of the authorization endpoint to the client (OAuth 2.0 Multiple Response
 * Type Encoding Practices §2.1). A mode the provider serves is a class tagged "heidi.response_mode", not a
 * branch added to a caller: what is tagged is what the parser accepts, what a request that asks for nothing
 * takes and what the discovery document announces.
 *
 * The mode names itself, under the name of the specification that defines it, and there is no enumeration
 * of modes anywhere. What a mode does beside delivering, it declares by the interfaces it implements next
 * to this one: SignsTheAnswerInterface for one whose answer is a document the tenant signs, and
 * AnswersTheJwtAliasInterface for the one "response_mode=jwt" resolves to. Nothing reads a mode by its name
 * to find out.
 */
interface AuthorizationResponseRendererInterface
{
    /**
     * The name of Multiple Response Type Encoding Practices §2.1, compared byte for byte with what a
     * request wrote.
     *
     * @return non-empty-string
     */
    public function mode(): string;

    public function render(AuthorizationAnswer $answer): Response;
}
