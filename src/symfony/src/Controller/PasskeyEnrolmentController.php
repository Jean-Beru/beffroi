<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Bundle\Http\PasskeysPage;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use function mb_strlen;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use function trim;

/**
 * The attestation of a new passkey, posted by the page of the account with the name the user gave it and
 * the CSRF token (architecture §5.2): verified by the enrolment of the core against the options this
 * browser was given for this user; the page comes back with the passkey listed, or with what went wrong.
 */
#[AsController]
final readonly class PasskeyEnrolmentController
{
    public const string ROUTE = 'heidi_interaction_account_passkeys_enrol';

    public const string CSRF_TOKEN_ID = 'heidi_passkey_enrol';

    public const string NAME_PARAMETER = 'name';

    public const string ATTESTATION_PARAMETER = '_passkey';

    public const string INVALID_NAME = 'invalid_name';

    public const string NO_CEREMONY = 'no_ceremony';

    public const string REFUSED = 'refused';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private PasskeyEnrolment $enrolment,
        private PasskeyOptionsStore $options,
        private PasskeysPage $page,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route('/account/passkeys', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        $name = trim($request->request->getString(self::NAME_PARAMETER));
        if ($name === '' || mb_strlen($name) > PasskeyCredential::NAME_MAX_LENGTH) {
            return $this->page->render($user, self::INVALID_NAME, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $attestation = $request->request->getString(self::ATTESTATION_PARAMETER);
        $options = $this->options->takeCreation($request->getSession(), $user->id);
        if ($attestation === '' || $options === null) {
            return $this->page->render($user, self::NO_CEREMONY, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        try {
            $this->enrolment->complete($user, $name, $options, $attestation, $this->contexts->fromRequest($request));
        } catch (CredentialEnrolmentFailedException) {
            return $this->page->render($user, self::REFUSED, Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        return $this->pages->redirect($this->router->generate(AccountPasskeysController::ROUTE));
    }
}
