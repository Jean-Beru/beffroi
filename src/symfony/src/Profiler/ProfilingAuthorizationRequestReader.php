<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_diff;
use function array_key_exists;
use function array_keys;
use Heidi\Bundle\Http\AuthorizationRequestReaderInterface;
use Heidi\Bundle\Http\ReceivedAuthorizationRequest;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Core\Domain\Tenant\Tenant;
use function implode;
use function is_scalar;
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
 * A value that is not a scalar is named and not printed: what a client puts under "claims" is a
 * structure. A parameter whose value is an assertion, a token, a proof or a secret is said to be there
 * and never written down, whether the endpoint reads it or not.
 */
final readonly class ProfilingAuthorizationRequestReader implements AuthorizationRequestReaderInterface
{
    /**
     * Parameters a request carries whose value is an assertion, a token or a proof; the panel says they
     * are there and never what they are.
     */
    private const array WITHHELD = ['request', 'id_token_hint', 'code_verifier', 'client_secret', 'client_assertion'];

    public function __construct(
        private AuthorizationRequestReaderInterface $reader,
        private OpProfile $profile,
    ) {
    }

    public function read(Tenant $tenant, Request $request): ReceivedAuthorizationRequest
    {
        $query = RequestParameters::ofBrowserRequest($request);
        $received = $this->reader->read($tenant, $request);
        $this->profile->record(new Observation('Authorization request', [
            'how it came in' => self::howItCameIn($received),
            'parameters read' => self::parameters($received->parameters),
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
     * @param array<string, mixed> $parameters
     */
    private static function parameters(array $parameters): string
    {
        $written = [];
        foreach ($parameters as $name => $value) {
            $written[] = $name . '=' . self::value($name, $value);
        }

        return $written === [] ? 'none' : implode("\n", $written);
    }

    private static function value(string $name, mixed $value): string
    {
        if (array_key_exists($name, self::withheld())) {
            return '(present, withheld)';
        }

        return is_scalar($value) ? (string) $value : '(a structure, withheld)';
    }

    /**
     * @return array<string, true>
     */
    private static function withheld(): array
    {
        $names = [];
        foreach (self::WITHHELD as $name) {
            $names[$name] = true;
        }

        return $names;
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
