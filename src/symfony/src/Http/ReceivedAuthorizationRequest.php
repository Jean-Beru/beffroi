<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

/**
 * The parameters of an authorization request as the provider reads them, and how they got there: the
 * query of the browser, the record of a request the client pushed (RFC 9126 §4), or the object it signed
 * (RFC 9101 §6.1). The two ways in drop everything of the query but "client_id", so which one carried
 * the request is what says where each parameter comes from.
 */
final readonly class ReceivedAuthorizationRequest
{
    /**
     * @param array<string, mixed> $parameters what the endpoint judges, whichever way the request came in
     * @param bool $pushed whether a record of the pushed authorization request endpoint carried it
     * @param bool $carriedByObject whether a request object carried it
     */
    public function __construct(
        public array $parameters,
        public bool $pushed,
        public bool $carriedByObject,
    ) {
    }
}
