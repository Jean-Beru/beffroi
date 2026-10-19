<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Saml\IdentityProviderRoutes;
use Beffroi\Bundle\Saml\SamlPostPage;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Saml\Application\SingleLogout\SingleLogout;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Exception\LogoutRefusedException;
use function explode;
use function strtolower;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use function trim;

/**
 * The single logout service of the SAML identity provider of the tenant (beffroi/saml, spec/saml.md section 6.5), at
 * the one URL its metadata publish for both bindings: HTTP-Redirect by GET, its raw query string read from
 * QUERY_STRING and never from the parsed query, whose octets the signature covers (B-2); HTTP-POST by POST, the fields
 * of a form and nothing else (spec/saml.md section 6.8). A request refused ends nothing and gets the page of a refusal
 * and no SAML answer (S-22, S-23); one accepted ends the sessions it names and is answered at the single logout service
 * of the metadata of its service provider, a 302 over HTTP-Redirect with the caching headers of the binding (SAML
 * Bindings §3.4.5.1), the page that posts the form over HTTP-POST (S-27). A tenant whose SAML key cannot be opened,
 * which is opened before the request is read, ends nothing and remembers nothing, whatever the request: a 404 when it
 * holds no active key, the 503 of KmsUnavailableListener when the KMS does not answer (S-23, S-27).
 *
 * The browser that held a session it ended finds none at its next request, the session of the core having ended.
 */
#[AsController]
final readonly class SamlSingleLogoutController
{
    /**
     * The error code of the page a refused logout request is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_logout_refused';

    /**
     * The one body HTTP-POST carries (SAML Bindings §3.5.4).
     */
    private const string FORM = 'application/x-www-form-urlencoded';

    public function __construct(
        private TenantProvider $tenants,
        private SingleLogout $singleLogout,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private SamlPostPage $page,
    ) {
    }

    #[Route(IdentityProviderRoutes::SINGLE_LOGOUT_PATH, name: IdentityProviderRoutes::SINGLE_LOGOUT, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $context = $this->contexts->fromRequest($request);
        try {
            if ($request->isMethod(Request::METHOD_POST)) {
                if (strtolower(trim(explode(';', $request->headers->get('Content-Type') ?? '')[0])) !== self::FORM) {
                    return $this->pages->error(
                        Response::HTTP_UNSUPPORTED_MEDIA_TYPE,
                        self::REFUSED,
                        'A request posted to the single logout service is a form, application/x-www-form-urlencoded (spec/saml.md section 6.8).',
                    );
                }
                $answer = $this->singleLogout->post($tenant, $request->request->all(), $context);
            } else {
                $answer = $this->singleLogout->redirect($tenant, $request->server->getString('QUERY_STRING'), $context);
            }
        } catch (LogoutRefusedException $exception) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $exception->getMessage());
        } catch (KeyNotFoundException) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, self::REFUSED, 'This tenant serves no SAML identity provider.');
        }
        if ($answer instanceof RedirectedMessage) {
            return new RedirectResponse($answer->url, Response::HTTP_FOUND, [
                ...InteractionPages::HEADERS,
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ]);
        }

        return $this->page->render($answer);
    }
}
