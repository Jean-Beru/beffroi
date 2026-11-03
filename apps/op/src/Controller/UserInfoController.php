<?php

declare(strict_types=1);

namespace App\Controller;

use App\Doctrine\TenantProvider;
use App\Http\DpopProofHeader;
use App\Http\RequestContextFactory;
use App\Http\RequestParameters;
use App\Http\ServesAProtectedResourceInterface;
use App\Http\Tls\PresentedClientCertificate;
use Beffroi\Oidc\Application\UserInfo\UserInfoHandler;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Beffroi\Oidc\Domain\UserInfo\UserInfoResponse;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Beffroi\Oidc\Port\ChallengeParametersInterface;
use Beffroi\Oidc\Port\ServedTokenSchemesInterface;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The UserInfo endpoint (OIDC Core §5.3), GET or POST; a GET hands the module no parameter at all
 * (RFC 6750 §2.3).
 *
 * It is a protected resource of the provider, the first one: an access token is presented here, and every
 * answer it writes names the exchange it belongs to (`FapiInteractionId`).
 */
#[AsController]
final readonly class UserInfoController implements ServesAProtectedResourceInterface
{
    public function __construct(
        private TenantProvider $tenants,
        private UserInfoHandler $handler,
        private RequestContextFactory $contexts,
        private PresentedClientCertificate $certificates,
        private ServedTokenSchemesInterface $schemes,
        private ChallengeParametersInterface $challenges,
    ) {
    }

    #[Route('/userinfo', name: 'beffroi_protocol_userinfo', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $response = $this->handler->handle(
                $this->tenants->provide(),
                $request->getMethod(),
                $request->headers->get('Authorization'),
                $request->isMethod('POST') ? RequestParameters::ofForm($request) : [],
                $this->contexts->fromRequest($request),
                $this->certificates->ofRequest($request),
                DpopProofHeader::ofRequest($request),
            );
        } catch (OAuth2Exception|MissingBearerTokenException $exception) {
            $error = UserInfoErrorResponse::fromException($exception, $this->schemes->servedTokenSchemes(), $this->challenges->challengeParameters());
            $parameters = $error->parameters();
            if ($parameters === []) {
                return new Response('', $error->statusCode, $error->headers());
            }

            return new Response(JwtPayload::encode($parameters), $error->statusCode, [
                'Content-Type' => UserInfoResponse::CONTENT_TYPE,
            ] + $error->headers());
        }

        return new Response($response->body, Response::HTTP_OK, [
            'Content-Type' => $response->contentType,
        ] + UserInfoResponse::HEADERS);
    }
}
