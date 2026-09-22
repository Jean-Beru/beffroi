<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Core\Exception\ExceptionTrail;
use Heidi\Oidc\Domain\EndSession\LogoutToken;
use function sprintf;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Carries one logout token to one relying party (Back-Channel Logout 1.0 §2.5): a POST of
 * "application/x-www-form-urlencoded" whose only parameter is "logout_token", no cookie, no
 * authentication, nothing read back but the status code. No redirect is followed (decision 0006): a
 * back-channel logout URI names where the token goes, and the provider does not let a third party move
 * it. The timeout is the sender's own, because a relying party that hangs must not hold a worker.
 */
final readonly class LogoutTokenSender
{
    /**
     * §2.5: the one parameter of the request.
     */
    public const string PARAMETER = 'logout_token';

    public function __construct(
        private HttpClientInterface $http,
        private float $timeout,
    ) {
    }

    public function send(string $logoutUri, string $logoutToken): LogoutTokenDelivery
    {
        try {
            $response = $this->http->request('POST', $logoutUri, [
                'body' => [
                    self::PARAMETER => $logoutToken,
                ],
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                    'Accept' => '*/*',
                ],
                'max_redirects' => 0,
                'timeout' => $this->timeout,
                'max_duration' => $this->timeout,
            ]);

            return self::outcomeOf($response->getStatusCode(), $response->getHeaders(false)['location'][0] ?? null);
        } catch (Throwable $exception) {
            return LogoutTokenDelivery::unreachable(sprintf('the client cannot be reached: %s', ExceptionTrail::of($exception)));
        }
    }

    /**
     * §2.8: 2xx is done, 400 and 501 are final. A redirect is final too, for a reason of our own: it is
     * the same answer every time and the provider does not follow it.
     */
    private static function outcomeOf(int $status, ?string $location): LogoutTokenDelivery
    {
        if ($status >= 200 && $status < 300) {
            return LogoutTokenDelivery::delivered($status);
        }
        if ($status >= 300 && $status < 400) {
            return LogoutTokenDelivery::refused(sprintf(
                'the client redirects to %s, and no outbound request follows a redirect; register that URL instead',
                $location ?? '?',
            ));
        }
        if ($status === 400 || $status === 501) {
            return LogoutTokenDelivery::refused(sprintf(
                'the client answered %d, which Back-Channel Logout 1.0 §2.8 makes final: it read the %s and refused it',
                $status,
                LogoutToken::TYPE,
            ));
        }

        return LogoutTokenDelivery::unreachable(sprintf('the client answered %d', $status));
    }
}
