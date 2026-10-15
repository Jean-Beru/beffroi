<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use function parse_url;
use const PHP_URL_HOST;
use const PHP_URL_PORT;
use const PHP_URL_SCHEME;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page that posts a SAML response to the assertion consumer service (beffroi/saml, spec/saml.md section 6.8,
 * spec/bindings.md section 6.7): the form PostSender returned, from a template an application may override, submitted
 * by one script its Content-Security-Policy names by its hash (CSP Level 3 §6.6.2.2), as the page of the form post
 * response mode names its own; nothing loads, nothing frames it, and the form posts to the origin of the assertion
 * consumer service and nowhere else. The caching headers are those of the binding (SAML Bindings §3.5.5.1).
 */
final readonly class SamlPostPage
{
    public const string TEMPLATE = 'saml_post.html.twig';

    /**
     * What submits the form where the browser runs scripts. A constant, because the hash of the policy is computed
     * from it.
     */
    public const string SCRIPT = 'document.forms[0].submit();';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    public function render(PostedForm $form): Response
    {
        return $this->pages->render(
            self::TEMPLATE,
            [
                'action' => $form->action,
                'fields' => $form->fields,
                'script' => self::SCRIPT,
            ],
            headers: [
                'Content-Security-Policy' => sprintf(
                    "default-src 'none'; script-src '%s'; form-action %s; base-uri 'none'; frame-ancestors 'none'",
                    new InlineScript(self::SCRIPT)->cspHashSource(),
                    self::originOf($form->action),
                ),
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ],
        );
    }

    /**
     * The scheme, the host and the port of the URL, which a "form-action" names (CSP Level 3 §2.3.1).
     */
    public static function originOf(string $url): string
    {
        $port = parse_url($url, PHP_URL_PORT);

        return sprintf(
            '%s://%s%s',
            (string) parse_url($url, PHP_URL_SCHEME),
            (string) parse_url($url, PHP_URL_HOST),
            $port === null || $port === false ? '' : ':' . $port,
        );
    }
}
