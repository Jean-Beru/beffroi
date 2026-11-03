<?php

declare(strict_types=1);

namespace App\Http\Tls;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Where the certificate a client presented comes from, for whoever needs one (architecture §5.2). One
 * implementation per shape of edge; the shape this application is delivered with is
 * EdgeClientCertificateResolver, and a deployment behind another proxy brings its own rather than
 * teaching this one a header to trust (decision 0006).
 */
interface ClientCertificateResolverInterface
{
    /**
     * The certificate this request was made with, or null when it was made without one, which is an
     * ordinary answer: the listener asks for a certificate, it does not require one.
     *
     * @throws ForgedClientCertificateException when the request carries a client certificate in a header,
     *                                          which nothing in front of this application sets
     * @throws InvalidArgumentException         when what the edge handed over is not a certificate
     */
    public function ofRequest(Request $request): ?ClientCertificate;
}
