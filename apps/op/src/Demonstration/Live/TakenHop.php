<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use App\Demonstration\Trace\FlowTrace;
use App\Demonstration\Trace\ProviderSideRecorder;
use App\Demonstration\Trace\TracedHop;
use function http_build_query;
use function is_array;
use function is_string;
use function json_decode;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * One hop taken for real (issue #462): the call is made to this provider, over HTTP, as any client
 * would make it, and both halves of it are written into the trace, the request as it was sent and the
 * answer as it came back. Nothing else reaches the trace, which is what makes a drawing of it unable to
 * show a payload that did not travel.
 *
 * The call carries the user agent of the demonstration, which is how the recorder of the provider's
 * side knows to leave this hop to the demonstration rather than record it a second time.
 *
 * A client that holds a secret authenticates with it (RFC 6749 §2.3.1) and that header is not drawn: a
 * picture of a flow is not a place to read a secret from. A public client names itself in the request,
 * where it really is, and that is drawn with the rest.
 */
final readonly class TakenHop
{
    public function __construct(
        private HttpClientInterface $http,
        private ClockInterface $clock,
    ) {
    }

    public function take(DrivenHopInterface $driven, DrivenCall $call, FlowTrace $trace, DemonstrationClient $client): FlowTrace
    {
        [$requestHop, $answerHop] = $driven->hops();
        $fields = $call->fields;
        if ($client->secret === null && $call->bearer === null) {
            // RFC 6749 §3.2.1: a client with no secret names itself in the request it authenticates
            // in. A call that presents a token authenticates nothing and names nobody: what it carries
            // is the token (RFC 6750 §2.1).
            $fields['client_id'] = $client->id;
        }
        $payload = http_build_query($fields);
        $url = $call->method === Request::METHOD_GET && $payload !== '' ? sprintf('%s?%s', $call->url, $payload) : $call->url;
        $trace = $trace->with(TracedHop::sent($requestHop, $this->clock->now(), $call->method, $url, $payload));

        $options = [
            'headers' => $this->headers($call),
        ];
        if ($call->method !== Request::METHOD_GET) {
            $options['body'] = $fields;
        }
        if ($client->secret !== null) {
            $options['auth_basic'] = [$client->id, $client->secret];
        }

        try {
            $response = $this->http->request($call->method, $url, $options);
            $status = $response->getStatusCode();
            $body = $response->getContent(false);
        } catch (TransportExceptionInterface $exception) {
            return $trace->with(TracedHop::unreachable($answerHop, $this->clock->now(), $exception->getMessage()));
        }

        $answer = json_decode($body, true);
        $answer = is_array($answer) ? $answer : [];

        return $trace->with(TracedHop::answered($answerHop, $this->clock->now(), $status, $body, self::refusal($answer)))->holding($driven->keeps($answer));
    }

    /**
     * @return array<string, string>
     */
    private function headers(DrivenCall $call): array
    {
        $headers = [
            'User-Agent' => ProviderSideRecorder::AGENT,
            'Accept' => 'application/json',
        ];
        if ($call->bearer !== null) {
            // RFC 6750 §2.1: the token is presented in the header, which is the one way this provider reads one
            $headers['Authorization'] = sprintf('Bearer %s', $call->bearer);
        }

        return $headers;
    }

    /**
     * What an answer that refuses says (RFC 6749 §5.2), and null for one that does not: the error and,
     * where there is one, the description beside it. It is what a hop that failed is drawn with, the
     * "authorization_pending" of a flow still waiting among them.
     *
     * @param array<array-key, mixed> $answer
     */
    private static function refusal(array $answer): ?string
    {
        $error = $answer['error'] ?? null;
        if (! is_string($error) || $error === '') {
            return null;
        }
        $description = $answer['error_description'] ?? null;

        return is_string($description) && $description !== ''
            ? sprintf('%s: %s', $error, $description)
            : $error;
    }
}
