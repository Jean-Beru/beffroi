<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use function array_diff;
use function array_keys;
use Beffroi\Bundle\Http\AuthorizationRequestReaderInterface;
use Beffroi\Bundle\Http\ReceivedAuthorizationRequest;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Core\Domain\Tenant\Tenant;
use function implode;
use Symfony\Component\HttpFoundation\Request;

/**
 * The authorization request as the provider understood it, beside the query the browser actually
 * carried: which parameters the record of a pushed request (RFC 9126 §4) or a request object
 * (OIDC Core §6.1) put there, which ones the query did, and which ones of the query were dropped because
 * one of those two spoke instead. That difference is the whole of what a browser stops showing once a
 * request is pushed or signed, which is why the panel exists at all.
 *
 * "client_id" is the one parameter both sides carry (RFC 9101 §5), and it is said to be so.
 *
 * The two sets are shown side by side, the query as the browser carried it and the request as the
 * provider read it, because a request that was pushed or signed makes them differ and that difference
 * is what a browser stops showing. A parameter whose value is an assertion, a token, a verifier or a
 * secret is said to be there and never written down, whether the endpoint reads it or not.
 */
final readonly class ProfilingAuthorizationRequestReader implements AuthorizationRequestReaderInterface
{
    public function __construct(
        private AuthorizationRequestReaderInterface $reader,
        private OpProfile $profile,
        private PanelValues $values,
    ) {
    }

    public function read(Tenant $tenant, Request $request): ReceivedAuthorizationRequest
    {
        $query = RequestParameters::ofBrowserRequest($request);
        $received = $this->reader->read($tenant, $request);
        $this->profile->record(new Observation('Request', 'Authorization request', [
            'how it came in' => self::howItCameIn($received),
            'the query the browser carried' => $this->values->all($query),
            'the request as the provider read it' => $this->values->all($received->parameters),
            'parameters of the query that were dropped' => self::dropped($query, $received),
        ]));

        return $received;
    }

    private static function howItCameIn(ReceivedAuthorizationRequest $received): string
    {
        if ($received->pushed) {
            return $received->carriedByObject
                ? 'pushed, and the record carries a request object (RFC 9126 section 4, RFC 9101 section 6.1)'
                : 'pushed, read back from the record (RFC 9126 section 4)';
        }

        return $received->carriedByObject
            ? 'carried by a request object, the query kept nothing but client_id (OIDC Core section 6.1)'
            : 'in the query of the browser';
    }

    /**
     * @param array<string, mixed> $query
     */
    private static function dropped(array $query, ReceivedAuthorizationRequest $received): string
    {
        if (! $received->pushed && ! $received->carriedByObject) {
            return 'none: the query is the request';
        }
        $dropped = array_diff(array_keys($query), array_keys($received->parameters));

        return $dropped === [] ? 'none' : implode(' ', $dropped);
    }
}
