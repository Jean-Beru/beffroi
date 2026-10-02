<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Tls;

use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Symfony\Component\HttpFoundation\Request;

/**
 * The certificate of a request as the protocol endpoints ask for it (RFC 8705 §2): the one the resolver
 * of the deployment read, or none, and an error of RFC 6749 §5.2 rather than a failure of the server
 * when the request tried to bring one of its own.
 *
 * The two refusals are the same answer on purpose. A request carrying a certificate in a header and a
 * request whose edge handed over something that is not a certificate are both requests this provider
 * cannot read as a client authentication, and "invalid_request" is what RFC 6749 §5.2 calls that. Which
 * header was tried is kept for whoever reads the logs and is not written back: an error description is
 * a sentence of the provider, never something the request chose (RFC 6749 §5.2).
 */
final readonly class PresentedClientCertificate
{
    public function __construct(
        private ClientCertificateResolverInterface $certificates,
    ) {
    }

    /**
     * @throws InvalidRequestException when the request carries a certificate in a header, or when what
     *                                 the edge handed over is not a certificate
     */
    public function ofRequest(Request $request): ?ClientCertificate
    {
        try {
            return $this->certificates->ofRequest($request);
        } catch (ForgedClientCertificateException $refusal) {
            throw new InvalidRequestException(
                'The request carries a client certificate in a header, which nothing in front of this provider sets.',
                previous: $refusal,
            );
        } catch (InvalidArgumentException $exception) {
            throw new InvalidRequestException('The client certificate of this request could not be read.', previous: $exception);
        }
    }
}
