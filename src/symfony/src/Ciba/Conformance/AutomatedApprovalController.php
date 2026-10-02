<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Ciba\Conformance;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\PasswordAuthenticator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Application\Ciba\BackchannelApproval;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use function is_string;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use function sprintf;

/**
 * What answers a backchannel request when the machine that made it is a certification suite and there is
 * nobody at the other end (CIBA Core §10.1, "automated_ciba_approval_url" of the OpenID conformance
 * suite, tests/conformance/README.md): the suite hands over the identifier of the request it is waiting
 * on and the answer it wants, and reads back what was done with it. The FAPI-CIBA plan has no browser in
 * it and its modules would otherwise each wait five minutes for a human.
 *
 * Not an API of the product and not imported by the routes of the bundle: an application imports it in
 * development only, under a prefix of its own, as it imports the endpoints of the FIDO2 server API.
 *
 * It answers with the calls the page answers with (PendingApprovalsController) and gains nothing the page
 * does not have. The user signs in first, with their password, exactly as they would on the login form,
 * because a session is opened on a proof here as everywhere (decision 0006); the request is then looked
 * for among the ones waiting for that user, so a request made for somebody else is no more answerable
 * through this than it is through the page. A request asking for a class that password does not prove is
 * refused here, where the page would send a browser to the login for one more proof (§7.1, decision
 * 0010): what a scripted client cannot do, it is told, and the module is not asked to make an exception.
 */
#[AsController]
final readonly class AutomatedApprovalController
{
    public const string ROUTE = 'beffroi_ciba_conformance_approval';

    /**
     * The identifier of the request, as the suite substitutes it into the URL it was configured with
     * ("{auth_req_id}").
     */
    public const string REQUEST_PARAMETER = 'auth_req_id';

    /**
     * What the suite wants done with it ("{action}"), the two words it substitutes.
     */
    public const string ANSWER_PARAMETER = 'action';

    public const string ANSWER_ALLOW = 'allow';

    public const string ANSWER_DENY = 'deny';

    /**
     * Who answers, and with what: the development user and the password "castor provision" wrote, both
     * of them values of the configuration of the suite, which already holds them for the login form its
     * scripted browser fills in the other plans.
     */
    public const string USERNAME_PARAMETER = 'username';

    public const string PASSWORD_PARAMETER = 'password';

    public function __construct(
        private TenantProvider $tenants,
        private PasswordAuthenticator $passwords,
        private BackchannelApproval $approval,
        private RequestContextFactory $contexts,
    ) {
    }

    #[Route('/approval', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $authRequestId = self::parameter($request, self::REQUEST_PARAMETER);
        $answer = self::parameter($request, self::ANSWER_PARAMETER);
        $username = self::parameter($request, self::USERNAME_PARAMETER);
        $password = self::parameter($request, self::PASSWORD_PARAMETER);
        if ($authRequestId === null || $username === null || $password === null) {
            return self::refused(sprintf(
                'The suite names the request with "%s" and the user with "%s" and "%s".',
                self::REQUEST_PARAMETER,
                self::USERNAME_PARAMETER,
                self::PASSWORD_PARAMETER,
            ));
        }
        if ($answer !== self::ANSWER_ALLOW && $answer !== self::ANSWER_DENY) {
            return self::refused(sprintf('The answer is "%s" or "%s".', self::ANSWER_ALLOW, self::ANSWER_DENY));
        }

        $context = $this->contexts->fromRequest($request);
        try {
            $session = $this->passwords->authenticate($this->tenants->provide(), $username, $password, $context);
        } catch (AuthenticationFailedException) {
            return self::refused(sprintf('The user "%s" did not sign in.', $username));
        }
        if (! $session instanceof AuthenticationSession) {
            // a user holding a second factor is held at the code, and the plans want the user "castor
            // provision" leaves behind, a password and nothing else (tests/conformance/README.md)
            return self::refused(sprintf('The user "%s" holds a second factor, and a password alone signs nobody in who does.', $username));
        }

        $record = $this->approval->awaitingAnAnswerFrom($session->user, DrawnSecret::digestOf($authRequestId));
        if ($record === null) {
            return self::refused('No request of that user is waiting for that identifier.');
        }
        if ($answer === self::ANSWER_DENY) {
            $this->approval->deny($record, $context);
        } else {
            if ($this->approval->stepUpFor($record, $session) !== null) {
                // the request asked for a class a password does not prove, and there is nobody here to
                // give one more proof: the page would ask, this answers what it cannot do (§7.1)
                return self::refused(sprintf('The request asks for a class the password of "%s" does not prove.', $username));
            }
            $this->approval->approve($record, $session, $context);
        }

        return new JsonResponse([
            'answer' => $answer,
            'client_id' => $record->clientId,
        ]);
    }

    /**
     * One value of the query, which is where the suite puts all of them: it posts the URL it was given
     * with no body at all.
     */
    private static function parameter(Request $request, string $name): ?string
    {
        $value = $request->query->get($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * Whatever the suite got wrong is answered with the reason: it logs the body of this call under the
     * module that made it, which is where an operator reads it.
     */
    private static function refused(string $reason): JsonResponse
    {
        return new JsonResponse([
            'error' => $reason,
        ], Response::HTTP_BAD_REQUEST);
    }
}
