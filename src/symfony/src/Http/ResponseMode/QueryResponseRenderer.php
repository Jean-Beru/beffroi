<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

use Heidi\Bundle\Http\InteractionPages;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Symfony\Component\HttpFoundation\Response;

/**
 * The default mode (RFC 6749 §4.1.2, Multiple Response Type Encoding Practices §2.1): the parameters in
 * the query of the redirect URI, the user agent sent there.
 */
final readonly class QueryResponseRenderer implements AuthorizationResponseRendererInterface
{
    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    public function mode(): ResponseMode
    {
        return ResponseMode::Query;
    }

    public function render(RedirectUri $redirectUri, array $parameters): Response
    {
        return $this->pages->redirect($redirectUri->withParameters($parameters));
    }
}
