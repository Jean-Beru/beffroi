<?php

declare(strict_types=1);

/*
 * The client side of "castor demo --register" (.castor/lab/demo.php, demo_register_check): a client this
 * provider had never seen writes its own registration, is answered credentials, signs a user in with them,
 * reads and changes itself at the URI it was handed, and deletes itself (RFC 7591, RFC 7592).
 *
 * It is the only client of the demonstration that is declared nowhere: every other one is a registration in
 * apps/op/config/packages/beffroi.yaml, which is the assumption this walk breaks. What it proves is that a
 * client nobody named gets exactly what a declared client gets and exactly the same refusals.
 *
 * The task is what runs under castor, which loads no code of the monorepo; this script runs under the
 * autoloader of the monorepo for its HTTP client, and holds no state between invocations: the walk carries
 * what one phase hands the next, because the browser step in the middle is the walk's and not the client's.
 *
 * Reads one JSON object on stdin, whose "action" says which phase to play, and writes one JSON object on
 * stdout. The phases are "register" (the registrations, the authorization request each client builds for
 * itself, and one registration beyond what the initial access token allows), "exchange" (each code for
 * tokens, and the "sub" the client is given), "configure" (itself read back, one member changed, a member
 * the provider does not offer refused, and the same read with no token) and "delete" (itself deleted, and
 * the token it held refused after).
 */

use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * A client that writes its own registration and lives at the URI the answer gave it.
 *
 * Nothing here is particular to this provider: the members are those of RFC 7591 §2, the credential is
 * presented as RFC 7591 §1.2 says, and the three operations on itself are those of RFC 7592 §2.
 */
final readonly class SelfRegisteringClient
{
    public function __construct(
        private HttpClientInterface $http,
    ) {
    }

    /**
     * RFC 7591 §3.1: the metadata posted as JSON, the initial access token presented as a bearer credential,
     * and a 201 that carries the credentials and the URI this client is now at.
     *
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    public function register(string $endpoint, array $metadata, ?string $initialAccessToken): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($initialAccessToken !== null && $initialAccessToken !== '') {
            $headers['Authorization'] = 'Bearer ' . $initialAccessToken;
        }

        return $this->answer($this->http->request('POST', $endpoint, [
            'headers' => $headers,
            'body' => (string) json_encode($metadata),
        ]));
    }

    /**
     * RFC 7592 §2.1: the client reads itself at its "registration_client_uri", presenting the
     * "registration_access_token" the registration handed it and nothing else.
     *
     * @return array<string, mixed>
     */
    public function read(string $uri, ?string $registrationAccessToken): array
    {
        $headers = [];
        if ($registrationAccessToken !== null && $registrationAccessToken !== '') {
            $headers['Authorization'] = 'Bearer ' . $registrationAccessToken;
        }

        return $this->answer($this->http->request('GET', $uri, ['headers' => $headers]));
    }

    /**
     * RFC 7592 §2.2: a replacement of the whole registration, which is why the metadata sent is everything
     * the client wants to be true of it and not the one member that changed.
     *
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    public function update(string $uri, array $metadata, string $registrationAccessToken): array
    {
        return $this->answer($this->http->request('PUT', $uri, [
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $registrationAccessToken,
            ],
            'body' => (string) json_encode($metadata),
        ]));
    }

    /**
     * RFC 7592 §2.3: the client removes itself, and nothing it held is worth anything afterwards.
     *
     * @return array<string, mixed>
     */
    public function delete(string $uri, string $registrationAccessToken): array
    {
        return $this->answer($this->http->request('DELETE', $uri, [
            'headers' => ['Authorization' => 'Bearer ' . $registrationAccessToken],
        ]));
    }

    /**
     * RFC 6749 §4.1.3 with PKCE (RFC 7636 §4.5): the code exchanged by the client the registration made,
     * authenticating with the secret that registration was answered.
     *
     * @return array<string, mixed>
     */
    public function exchange(
        string $tokenEndpoint,
        string $clientId,
        string $clientSecret,
        string $code,
        string $redirectUri,
        string $codeVerifier,
    ): array {
        return $this->answer($this->http->request('POST', $tokenEndpoint, [
            'auth_basic' => [$clientId, $clientSecret],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'code_verifier' => $codeVerifier,
            ],
        ]));
    }

    /**
     * The status and the body of an answer, whatever it is: a refusal is a result here and never an
     * exception, because every refusal this walk plays is asserted.
     *
     * @return array<string, mixed>
     */
    private function answer(ResponseInterface $response): array
    {
        try {
            $status = $response->getStatusCode();
            $content = $response->getContent(false);
        } catch (HttpExceptionInterface $exception) {
            return [
                'status' => 0,
                'transport_error' => $exception->getMessage(),
            ];
        }
        $body = json_decode($content, true);

        return [
            'status' => $status,
            'body' => is_array($body) ? $body : null,
            'raw' => is_array($body) ? null : $content,
        ];
    }
}

/**
 * RFC 7636 §4.1 and §4.2: the verifier the client keeps and the challenge it sends.
 *
 * @return array{verifier: string, challenge: string}
 */
function registration_pkce(): array
{
    $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

    return [
        'verifier' => $verifier,
        'challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
    ];
}

/**
 * The claims of a JWS, read and not verified: what this script needs of an ID token is the "sub" the
 * provider gave this client, and the walk compares two of them. A client that verifies is the ladder.
 *
 * @return array<string, mixed>
 */
function registration_claims(string $jwt): array
{
    $parts = explode('.', $jwt);
    if (count($parts) < 2) {
        return [];
    }
    $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);

    return is_array($claims) ? registration_named($claims) : [];
}

/**
 * A JSON object as the members it has: decoded, its keys are whatever they were written as, and a key made
 * of digits names no member.
 *
 * @param array<array-key, mixed> $decoded
 *
 * @return array<string, mixed>
 */
function registration_named(array $decoded): array
{
    $named = [];
    foreach ($decoded as $name => $value) {
        $named[(string) $name] = $value;
    }

    return $named;
}

/**
 * @param array<string, mixed> $input
 */
function registration_text(array $input, string $member): string
{
    $value = $input[$member] ?? null;

    return is_string($value) && $value !== '' ? $value : throw new RuntimeException(sprintf('The input carries no "%s".', $member));
}

/**
 * A member that is itself a JSON object; the empty one when it is absent, for the members that are optional.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function registration_map(array $input, string $member): array
{
    $value = $input[$member] ?? null;

    return is_array($value) ? registration_named($value) : [];
}

/**
 * The two registrations, the authorization request each client builds for itself, and the ones the
 * credential does not buy: one beyond what it was issued for, and one presenting nothing at all.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function registration_phase_register(SelfRegisteringClient $client, array $input): array
{
    $endpoint = registration_text($input, 'registration_endpoint');
    $authorizationEndpoint = registration_text($input, 'authorization_endpoint');
    $token = registration_text($input, 'initial_access_token');
    $out = ['registered' => []];
    foreach (registration_map($input, 'clients') as $key => $wanted) {
        $metadata = registration_map(is_array($wanted) ? registration_named($wanted) : [], 'metadata');
        $answered = $client->register($endpoint, $metadata, $token);
        $body = registration_map($answered, 'body');
        $redirects = $metadata['redirect_uris'] ?? null;
        $redirect = is_array($redirects) && is_string($redirects[0] ?? null) ? $redirects[0] : '';
        $scope = is_string($metadata['scope'] ?? null) ? $metadata['scope'] : 'openid';
        $pkce = registration_pkce();
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        // The client builds its own authorization request, which is what makes it a client: the walk
        // plays only the browser that carries it (RFC 6749 §4.1.1, RFC 7636 §4.3).
        $authorization = is_string($body['client_id'] ?? null)
            ? $authorizationEndpoint
            . '?'
            . http_build_query([
                'response_type' => 'code',
                'client_id' => $body['client_id'],
                'redirect_uri' => $redirect,
                'scope' => $scope,
                'state' => $state,
                'nonce' => $nonce,
                'code_challenge' => $pkce['challenge'],
                'code_challenge_method' => 'S256',
            ])
            : null;
        $out['registered'][$key] = $answered
        + [
            'authorization_url' => $authorization,
            'code_verifier' => $pkce['verifier'],
            'state' => $state,
            'nonce' => $nonce,
        ];
    }
    $out['beyond'] = $client->register($endpoint, registration_map($input, 'beyond'), $token);
    $out['without_token'] = $client->register($endpoint, registration_map($input, 'without_token'), null);

    return $out;
}

/**
 * Each code exchanged by the client the registration made, and the subject it is given.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function registration_phase_exchange(SelfRegisteringClient $client, array $input): array
{
    $tokenEndpoint = registration_text($input, 'token_endpoint');
    $out = ['exchanged' => []];
    foreach (registration_map($input, 'clients') as $key => $each) {
        $one = is_array($each) ? registration_named($each) : [];
        $answered = $client->exchange(
            $tokenEndpoint,
            registration_text($one, 'client_id'),
            registration_text($one, 'client_secret'),
            registration_text($one, 'code'),
            registration_text($one, 'redirect_uri'),
            registration_text($one, 'code_verifier'),
        );
        $body = registration_map($answered, 'body');
        $claims = is_string($body['id_token'] ?? null) ? registration_claims($body['id_token']) : [];
        $out['exchanged'][$key] = [
            'status' => $answered['status'] ?? 0,
            'error' => $body['error'] ?? null,
            'error_description' => $body['error_description'] ?? null,
            'token_type' => $body['token_type'] ?? null,
            'scope' => $body['scope'] ?? null,
            'sub' => $claims['sub'] ?? null,
            'nonce' => $claims['nonce'] ?? null,
            'aud' => $claims['aud'] ?? null,
            'access_token_claims' => is_string($body['access_token'] ?? null)
                ? registration_claims($body['access_token'])
                : [],
        ];
    }

    return $out;
}

/**
 * Itself read back, itself replaced, and the two reads no token of this client authorises.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function registration_phase_configure(SelfRegisteringClient $client, array $input): array
{
    $uri = registration_text($input, 'registration_client_uri');
    $token = registration_text($input, 'registration_access_token');
    $another = $input['another_token'] ?? null;

    return [
        'read' => $client->read($uri, $token),
        'read_without_token' => $client->read($uri, null),
        'read_with_another_token' => is_string($another) ? $client->read($uri, $another) : null,
        'updated' => $client->update($uri, registration_map($input, 'replacement'), $token),
        'refused' => $client->update($uri, registration_map($input, 'refused'), $token),
    ];
}

/**
 * Itself removed, and the token it held worth nothing afterwards.
 *
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function registration_phase_delete(SelfRegisteringClient $client, array $input): array
{
    $uri = registration_text($input, 'registration_client_uri');
    $token = registration_text($input, 'registration_access_token');

    return [
        'deleted' => $client->delete($uri, $token),
        'read_after' => $client->read($uri, $token),
    ];
}

$read = json_decode((string) file_get_contents('php://stdin'), true, 16, JSON_THROW_ON_ERROR);
if (! is_array($read)) {
    throw new RuntimeException('This program reads one JSON object on its standard input.');
}
$input = registration_named($read);
$cafile = registration_text($input, 'cafile');
$client = new SelfRegisteringClient(HttpClient::create(['cafile' => $cafile]));
$phase = registration_text($input, 'action');

$answer = match ($phase) {
    'register' => registration_phase_register($client, $input),
    'exchange' => registration_phase_exchange($client, $input),
    'configure' => registration_phase_configure($client, $input),
    'delete' => registration_phase_delete($client, $input),
    default => throw new RuntimeException(sprintf('No phase "%s" of the registration client.', $phase)),
};

fwrite(STDOUT, json_encode($answer, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
