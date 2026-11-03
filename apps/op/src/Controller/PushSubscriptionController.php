<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\WhatWasRefused;
use Beffroi\Core\Application\Push\PushSubscriptionEnrolment;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Port\ApplicationServerAlgorithmsInterface;
use function mb_strlen;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use function trim;

/**
 * What the browser of the signed-in user hands over once its push service has given it a subscription
 * (Push API §3.4, §8, architecture §5.2): where a message for it is taken and the two keys one is
 * encrypted to. Posted by the script of the page with the token that page renders, and recorded against
 * the application server key the browser was handed, which is what will sign a push to it
 * (RFC 8292 §3.2).
 *
 * A browser that subscribes again hands back the endpoint it already had, and that is one browser and not
 * two: the row it has is what changes.
 *
 * It answers with a redirection whether the ceremony was completed or refused (issue #481): a browser
 * reloading the page it comes back to does not present the same thing again, and what was refused crosses
 * the redirection in the session (WhatWasRefused).
 */
#[AsController]
final readonly class PushSubscriptionController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_notifications_subscribe';

    public const string CSRF_TOKEN_ID = 'beffroi_push_subscribe';

    public const string ENDPOINT_PARAMETER = 'endpoint';

    public const string PUBLIC_KEY_PARAMETER = 'p256dh';

    public const string AUTH_SECRET_PARAMETER = 'auth';

    public const string LABEL_PARAMETER = 'label';

    /**
     * What a user may call one of their browsers, in the column that holds it.
     */
    public const int LABEL_MAX_LENGTH = 255;

    public const string NOT_SERVED = 'not_served';

    public const string REFUSED = 'refused';

    public function __construct(
        private AccountAccess $account,
        private ApplicationServerAlgorithmsInterface $algorithms,
        private PushSubscriptionEnrolment $enrolment,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/notifications', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        $algorithm = $this->algorithms->all()[0] ?? null;
        if ($algorithm === null) {
            return $this->refused($request, self::NOT_SERVED);
        }
        $label = trim($request->request->getString(self::LABEL_PARAMETER));
        try {
            $this->enrolment->enrol(
                $user,
                $algorithm,
                $request->request->getString(self::ENDPOINT_PARAMETER),
                $request->request->getString(self::PUBLIC_KEY_PARAMETER),
                $request->request->getString(self::AUTH_SECRET_PARAMETER),
                $label === '' || mb_strlen($label) > self::LABEL_MAX_LENGTH ? null : $label,
            );
        } catch (InvalidArgumentException) {
            return $this->refused($request, self::REFUSED);
        } catch (KeyNotFoundException) {
            return $this->refused($request, self::NOT_SERVED);
        }

        return $this->pages->afterTheForm(AccountNotificationsController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(AccountNotificationsController::ROUTE);
    }
}
