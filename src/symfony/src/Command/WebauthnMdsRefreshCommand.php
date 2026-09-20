<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use function count;
use function file_get_contents;
use function hash;
use Heidi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Heidi\Core\Exception\MetadataBlobRefusedException;
use Heidi\Core\Port\MetadataBlobStoreInterface;
use function is_string;
use function parse_url;
use const PHP_URL_HOST;
use function sprintf;
use function str_starts_with;
use function substr;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;

/**
 * The FIDO metadata the ceremonies check an attestation against (architecture §3.4), refreshed by hand:
 * the Metadata BLOB downloaded (FIDO Metadata Service v3 §3.1), its signature and its chain verified up to
 * the root this command pins (§3.2), its payload stored. Nothing refreshes it on its own: that is a service
 * of the hosted offer, and a provider that never ran this command knows no authenticator, which its own
 * enrolment does not need (it asks for no attestation).
 */
#[AsCommand(
    name: 'heidi:webauthn:mds-refresh',
    description: 'Download the FIDO Metadata BLOB, verify its signature under the pinned root and store it for the passkey ceremonies; --url for another service, --root for another root.',
)]
final readonly class WebauthnMdsRefreshCommand
{
    /**
     * Where the FIDO Alliance serves its blob (https://fidoalliance.org/metadata/); the "mds3" host of the
     * documentation answers with a redirect to this one, which no outbound request follows (decision 0006).
     */
    public const string FIDO_METADATA_SERVICE = 'https://mds.fidoalliance.org/';

    /**
     * The root the FIDO Alliance signs under, shipped with the bundle.
     */
    public const string FIDO_ROOT_CERTIFICATE = __DIR__ . '/../../config/webauthn/globalsign-root-ca-r3.pem';

    public function __construct(
        private HttpClientInterface $http,
        private MetadataBlobVerifier $verifier,
        private MetadataBlobStoreInterface $store,
    ) {
    }

    /**
     * @param list<string> $url
     */
    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'The URL of a Metadata BLOB, repeatable; the FIDO Metadata Service unless given.')]
        array $url = [],
        #[Option(description: 'The root certificate the chain of a blob must lead to: a PEM or DER file, or an https URL; the GlobalSign Root CA - R3 the FIDO Alliance signs under unless given.')]
        ?string $root = null,
    ): int {
        try {
            $rootCertificate = $this->rootCertificate($root ?? self::FIDO_ROOT_CERTIFICATE);
        } catch (Throwable $exception) {
            $io->error(sprintf('The root certificate cannot be read: %s', $exception->getMessage()));

            return Command::FAILURE;
        }
        $refused = 0;
        foreach ($url === [] ? [self::FIDO_METADATA_SERVICE] : $url as $source) {
            if (! is_string($source)) {
                continue;
            }
            try {
                $blob = $this->verifier->verify($this->download($source), $rootCertificate);
            } catch (MetadataBlobRefusedException $exception) {
                ++$refused;
                $io->error(sprintf('The blob of %s is refused, nothing of it is kept: %s', $source, $exception->getMessage()));
                continue;
            }
            $name = self::name($source);
            $this->store->write($name, $blob->payload);
            $io->success(sprintf('The blob of %s is stored as "%s": serial number %d, %d entries, next update due on %s.', $source, $name, $blob->content->no, count($blob->content->entries), $blob->content->nextUpdate));
        }

        return $refused === 0 ? Command::SUCCESS : Command::FAILURE;
    }

    /**
     * @throws MetadataBlobRefusedException when the service does not answer with a document
     */
    private function download(string $url): string
    {
        try {
            $response = $this->http->request('GET', $url, [
                'max_redirects' => 0,
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                $location = $response->getHeaders(false)['location'][0] ?? '?';
                throw new MetadataBlobRefusedException(sprintf('the service redirects to %s, and no outbound request follows a redirect; name that URL instead', $location));
            }
            if ($status !== 200) {
                throw new MetadataBlobRefusedException(sprintf('the service answered %d', $status));
            }

            return $response->getContent();
        } catch (MetadataBlobRefusedException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new MetadataBlobRefusedException(sprintf('the service cannot be reached: %s', $exception->getMessage()), previous: $exception);
        }
    }

    /**
     * The root as PEM, from a file or from an https URL (no redirect followed either).
     */
    private function rootCertificate(string $root): string
    {
        if (str_starts_with($root, 'https://')) {
            $response = $this->http->request('GET', $root, [
                'max_redirects' => 0,
            ]);
            $certificate = $response->getContent();
        } else {
            $certificate = file_get_contents($root);
            if ($certificate === false) {
                throw new MetadataBlobRefusedException(sprintf('"%s" cannot be read.', $root));
            }
        }

        return CertificateToolbox::convertDERToPEM($certificate);
    }

    /**
     * The name a source keeps in the store, so that a refresh replaces the document of the same source:
     * its host, and a digest of the whole URL.
     *
     * @return non-empty-string
     */
    private static function name(string $url): string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return sprintf('mds-%s-%s', is_string($host) ? $host : 'unnamed', substr(hash('sha256', $url), 0, 8));
    }
}
