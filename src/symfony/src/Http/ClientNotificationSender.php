<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Core\Exception\ExceptionTrail;
use function sprintf;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Tells one client that the backchannel request it made has been answered (CIBA Core §10.2): a POST of
 * "application/json" whose only member is the identifier of that request, carrying the token that client
 * sent with it, nothing read back but the status code. No cookie, no redirect followed (decision 0006):
 * a notification endpoint names where the word goes, and the provider does not let a third party move it.
 *
 * No token is ever carried here (§10.3 is not served): what the client is told is that there is something
 * to come and get, and it comes to the token endpoint for it, which is where a client that only polls
 * would have found the same answer.
 *
 * The timeout is the sender's own, because a client that hangs must not hold a worker.
 */
final readonly class ClientNotificationSender
{
    /**
     * §10.2: the one member of the body.
     */
    public const string PARAMETER = 'auth_req_id';

    public function __construct(
        private HttpClientInterface $http,
        public float $timeout,
    ) {
    }

    public function send(string $notificationEndpoint, string $notificationToken, string $authRequestId): OutboundDelivery
    {
        try {
            $response = $this->http->request('POST', $notificationEndpoint, [
                'json' => [
                    self::PARAMETER => $authRequestId,
                ],
                'headers' => [
                    'Authorization' => 'Bearer ' . $notificationToken,
                    'Accept' => '*/*',
                ],
                'max_redirects' => 0,
                'timeout' => $this->timeout,
                'max_duration' => $this->timeout,
            ]);

            return self::outcomeOf($response->getStatusCode(), $response->getHeaders(false)['location'][0] ?? null);
        } catch (Throwable $exception) {
            return OutboundDelivery::unreachable(sprintf('the client cannot be reached: %s', ExceptionTrail::of($exception)));
        }
    }

    /**
     * §10.2: 2xx is done. A client that refuses the token it gave us, or the request itself, says the
     * same thing every time and is given up on at once rather than told again and again with a
     * credential it has already rejected. A redirect is final too: the provider does not follow it.
     */
    private static function outcomeOf(int $status, ?string $location): OutboundDelivery
    {
        if ($status >= 200 && $status < 300) {
            return OutboundDelivery::delivered($status);
        }
        if ($status >= 300 && $status < 400) {
            return OutboundDelivery::refused(sprintf(
                'the client redirects to %s, and no outbound request follows a redirect; register that URL instead',
                $location ?? '?',
            ));
        }
        if ($status === 400 || $status === 401 || $status === 403 || $status === 404 || $status === 405 || $status === 501) {
            return OutboundDelivery::refused(sprintf(
                'the client answered %d, which says it read the notification and will not take it; the same answer would come back on every retry',
                $status,
            ));
        }

        return OutboundDelivery::unreachable(sprintf('the client answered %d', $status));
    }
}
