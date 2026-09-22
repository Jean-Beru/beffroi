<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\Tls;

use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Symfony\Component\HttpFoundation\Request;

/**
 * The certificate read from what the edge proves (docs/mtls-at-the-edge.md): a server variable the TLS
 * listener fills from the handshake it carried out itself, never a header.
 *
 * The difference is the whole rule of decision 0006. A client controls every header of its request and
 * no variable of the process that serves it: a client sending "Ssl-Client-Cert" reaches PHP as
 * HTTP_SSL_CLIENT_CERT, which nothing here reads, while SSL_CLIENT_CERT exists only where the
 * configuration of the listener puts it. A request that carries one of those headers all the same is
 * somebody trying, and is refused rather than served without its certificate, so that a deployment put
 * behind a proxy that forwards one says so on the first request instead of trusting it silently.
 */
final readonly class EdgeClientCertificateResolver implements ClientCertificateResolverInterface
{
    /**
     * The variable the listener fills with the leaf, named after mod_ssl's SSL_CLIENT_CERT and nginx's
     * $ssl_client_cert, in the PEM envelope both of them use.
     */
    public const string VARIABLE = 'SSL_CLIENT_CERT';

    /**
     * The headers proxies carry a client certificate in. None of them is read; each of them is refused.
     */
    public const array REFUSED_HEADERS = [
        'ssl-client-cert',
        'x-ssl-client-cert',
        'x-client-cert',
        'x-forwarded-client-cert',
    ];

    public function ofRequest(Request $request): ?ClientCertificate
    {
        foreach (self::REFUSED_HEADERS as $header) {
            if ($request->headers->has($header)) {
                throw ForgedClientCertificateException::carriedBy($header);
            }
        }
        $pem = $request->server->getString(self::VARIABLE);
        if ($pem === '') {
            return null;
        }

        return ClientCertificate::fromPem($pem);
    }
}
