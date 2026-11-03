<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Webauthn;

use function sprintf;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * What the console downloads for the passkeys of the deployment (architecture §3.4, §5.5), the Metadata BLOB of
 * the FIDO Alliance and the list of the community: one GET and its answer whole, no redirect followed (decision
 * 0006), the URL a redirect leads to named so that whoever runs the command can name it instead, and an answer
 * other than 200 refused with its status.
 */
final readonly class DocumentDownload
{
    public function __construct(
        private HttpClientInterface $http,
    ) {
    }

    /**
     * @throws DownloadRefusedException when the service redirects, answers anything but 200, or cannot be reached
     */
    public function of(string $url): string
    {
        try {
            $response = $this->http->request('GET', $url, [
                'max_redirects' => 0,
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                throw new DownloadRefusedException(sprintf(
                    'the service redirects to %s, and no outbound request follows a redirect; name that URL instead',
                    $response->getHeaders(false)['location'][0] ?? '?',
                ));
            }
            if ($status !== 200) {
                throw new DownloadRefusedException(sprintf('the service answered %d', $status));
            }

            return $response->getContent();
        } catch (DownloadRefusedException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new DownloadRefusedException(sprintf('the service cannot be reached: %s', $exception->getMessage()), previous: $exception);
        }
    }
}
