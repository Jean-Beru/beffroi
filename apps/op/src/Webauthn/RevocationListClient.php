<?php

declare(strict_types=1);

namespace App\Webauthn;

use function str_starts_with;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * The client the certificate chains of WebAuthn download their revocation lists with: what webauthn-lib's
 * PhpCertificateChainValidator asks, for the chain of a Metadata BLOB and for the chain of an attestation,
 * the request being the library's and the client the provider's. No redirect is followed (decision 0006), but
 * one (decision 0035): the test service of the FIDO Alliance names its revocation lists on the host its
 * documentation gives and serves them from another, so a request to that host follows its redirect once, to
 * that other host only, and no further. A redirect that is not that one comes back as it is, a list the
 * library cannot download.
 */
final readonly class RevocationListClient implements HttpClientInterface
{
    /**
     * Where the certificates of the MDS3 test service of the FIDO Alliance name their revocation lists
     * ("https://mds3.certinfra.fidoalliance.org/crl/MDSCA-1.crl"), the address the documentation of the
     * conformance tools gives for the service.
     */
    public const string FIDO_TEST_SERVICE = 'https://mds3.certinfra.fidoalliance.org/';

    /**
     * Where that address redirects, and the one origin a revocation list is followed to.
     */
    public const string FIDO_TEST_SERVICE_HOST = 'https://mds3.fido.tools/';

    public function __construct(
        private HttpClientInterface $http,
    ) {
    }

    /**
     * @param array<mixed> $options
     */
    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $response = $this->http->request($method, $url, [
            'max_redirects' => 0,
        ] + $options);
        if (! str_starts_with($url, self::FIDO_TEST_SERVICE)) {
            return $response;
        }
        $status = $response->getStatusCode();
        if ($status < 300 || $status >= 400) {
            return $response;
        }
        $location = $response->getHeaders(false)['location'][0] ?? '';
        if (! str_starts_with($location, self::FIDO_TEST_SERVICE_HOST)) {
            return $response;
        }

        return $this->http->request($method, $location, [
            'max_redirects' => 0,
        ] + $options);
    }

    public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
    {
        return $this->http->stream($responses, $timeout);
    }

    /**
     * @param array<mixed> $options
     */
    public function withOptions(array $options): static
    {
        return new self($this->http->withOptions($options));
    }
}
