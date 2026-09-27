<?php

declare(strict_types=1);

/*
 * The signing side of "castor demo --assertion" (.castor/lab/demo.php, demo_assertion_check): a client that
 * presents an assertion signed by an issuer the tenant trusts and is answered with an access token for the
 * user that assertion names (RFC 7523 §2.1). The task is what runs under castor, which loads no code of the
 * monorepo; this script runs under the autoloader of the monorepo, so that the assertion is signed with the
 * key the provider was given the public half of.
 *
 * It plays the trust decision whole, and a trust decision is what its refusals are: one assertion is
 * exchanged once, an assertion about somebody no linked identity resolves buys nothing, and "openid" is not
 * something this grant may hand out, because nobody authenticated in it. Every refusal comes back saying the
 * same thing, which is the point: what a tenant trusts is not something an error response teaches.
 *
 * Reads one JSON object on stdin: "token_endpoint", "cafile" (the CA of the OP), "client_id",
 * "client_secret", "trusted_issuer" (the "iss" its assertions carry), "audience" (the issuer identifier of
 * the provider, the one name an assertion may be addressed to), "subject" (the user, as the issuer names
 * them), "unknown_subject", "scope", "resource" and "jwks_file" (where "castor provision" left the private
 * half). Writes one JSON object on stdout: what each of the four attempts was answered.
 */

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * An issuer whose signature a tenant trusts, as far as this demonstration is concerned: it signs assertions
 * about the users it knows, and the client below presents them (RFC 7523 §3). Whoever holds this key can name
 * a user of that tenant, which is why the provider was given the public half alone and why the registration
 * names both the client that may present these assertions and the source their subjects resolve through.
 */
final readonly class TrustedIssuerSigner
{
    private const string ALGORITHM = 'ES256';

    private JWSBuilder $jws;

    private CompactSerializer $serializer;

    public function __construct(
        private JWK $key,
        private string $issuer,
        private string $audience,
    ) {
        $this->jws = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * RFC 7523 §3: the issuer, the subject it is about, this provider as the one audience, a lifetime, and an
     * identifier of its own, which is what makes the assertion good once.
     */
    public function sign(string $subject, int $lifetime = 60): string
    {
        $now = time();
        $claims = [
            'iss' => $this->issuer,
            'sub' => $subject,
            'aud' => $this->audience,
            'iat' => $now,
            'exp' => $now + $lifetime,
            // drawn, never counted: an identifier a replay guard remembers must not be one another party
            // can produce
            'jti' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
        ];
        $jws = $this->jws
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($this->key, [
                'alg' => self::ALGORITHM,
                'kid' => $this->key->get('kid'),
                'typ' => 'JWT',
            ])
            ->build();

        return $this->serializer->serialize($jws, 0);
    }
}

/**
 * The client that presents those assertions. It authenticates with its own credentials beside the assertion
 * and never with it: the assertion is the authorization, and the two readings of an assertion share nothing
 * (RFC 7523 §2.1, last paragraph).
 */
final readonly class AssertionClient
{
    public const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    private HttpClientInterface $http;

    public function __construct(
        string $cafile,
        private string $tokenEndpoint,
        private string $clientId,
        private string $secret,
    ) {
        $this->http = HttpClient::create([
            'max_redirects' => 0,
            'cafile' => $cafile,
        ]);
    }

    /**
     * One attempt, and what the provider answered it: the status, the error when there is one, and what the
     * token says of itself when there is a token.
     *
     * @return array<string, mixed>
     */
    public function present(string $assertion, string $scope, string $resource): array
    {
        try {
            $response = $this->http->request('POST', $this->tokenEndpoint, [
                'auth_basic' => $this->clientId . ':' . $this->secret,
                'body' => [
                    'grant_type' => self::GRANT_TYPE,
                    'assertion' => $assertion,
                    'scope' => $scope,
                    'resource' => $resource,
                ],
            ]);
            $status = $response->getStatusCode();
            $decoded = json_decode($response->getContent(false), true, 8, JSON_THROW_ON_ERROR);
        } catch (HttpExceptionInterface|JsonException $exception) {
            return [
                'status' => 0,
                'error' => 'unreadable',
                'error_description' => $exception->getMessage(),
            ];
        }
        $answer = is_array($decoded) ? $decoded : [];
        $accessToken = $answer['access_token'] ?? null;

        return [
            'status' => $status,
            'error' => is_string($answer['error'] ?? null) ? $answer['error'] : null,
            'error_description' => is_string($answer['error_description'] ?? null) ? $answer['error_description'] : null,
            'token_type' => is_string($answer['token_type'] ?? null) ? $answer['token_type'] : null,
            'scope' => is_string($answer['scope'] ?? null) ? $answer['scope'] : null,
            'expires_in' => is_int($answer['expires_in'] ?? null) ? $answer['expires_in'] : null,
            'id_token' => isset($answer['id_token']),
            'refresh_token' => isset($answer['refresh_token']),
            'claims' => is_string($accessToken) ? self::claimsOf($accessToken) : [],
        ];
    }

    /**
     * RFC 9068 §2.2: what the token says of itself, read to report it; nothing is verified here, this being
     * the client and not a resource server.
     *
     * @return array<string, mixed>
     */
    private static function claimsOf(string $accessToken): array
    {
        $parts = explode('.', $accessToken);
        if (count($parts) !== 3) {
            return [];
        }
        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true, 8);

        return is_array($payload) ? assertion_cli_named($payload) : [];
    }
}

/**
 * @param array<string, mixed> $input
 */
function assertion_cli_text(array $input, string $member): string
{
    $value = $input[$member] ?? null;

    return is_string($value) && $value !== '' ? $value : throw new RuntimeException(sprintf('The input carries no "%s".', $member));
}

/**
 * A JSON object as the members it has: decoded, its keys are whatever they were written as, and a key made of
 * digits names no member.
 *
 * @param array<array-key, mixed> $decoded
 *
 * @return array<string, mixed>
 */
function assertion_cli_named(array $decoded): array
{
    $named = [];
    foreach ($decoded as $name => $value) {
        $named[(string) $name] = $value;
    }

    return $named;
}

$read = json_decode((string) file_get_contents('php://stdin'), true, 8, JSON_THROW_ON_ERROR);
if (! is_array($read)) {
    throw new RuntimeException('This program reads one JSON object on its standard input.');
}
$input = assertion_cli_named($read);
$set = json_decode((string) file_get_contents(assertion_cli_text($input, 'jwks_file')), true, 8, JSON_THROW_ON_ERROR);
$keys = is_array($set) && is_array($set['keys'] ?? null) ? $set['keys'] : [];
$key = is_array($keys[0] ?? null) ? new JWK($keys[0]) : throw new RuntimeException('The JWK Set of the trusted issuer carries no key.');
$signer = new TrustedIssuerSigner($key, assertion_cli_text($input, 'trusted_issuer'), assertion_cli_text($input, 'audience'));
$client = new AssertionClient(
    assertion_cli_text($input, 'cafile'),
    assertion_cli_text($input, 'token_endpoint'),
    assertion_cli_text($input, 'client_id'),
    assertion_cli_text($input, 'client_secret'),
);
$subject = assertion_cli_text($input, 'subject');
$scope = assertion_cli_text($input, 'scope');
$resource = assertion_cli_text($input, 'resource');

// The one that works, then the three refusals, each one a rule of the grant and not an accident: the same
// assertion again (RFC 7523 §3, the replay guard), one about somebody no linked identity resolves (decision
// 0002), and one asking for an authentication this grant performs for nobody (OIDC Core §2).
$assertion = $signer->sign($subject);
$granted = $client->present($assertion, $scope, $resource);
$replayed = $client->present($assertion, $scope, $resource);
$unknown = $client->present($signer->sign(assertion_cli_text($input, 'unknown_subject')), $scope, $resource);
$openid = $client->present($signer->sign($subject), 'openid ' . $scope, $resource);

fwrite(STDOUT, json_encode(
    [
        'granted' => $granted,
        'replayed' => $replayed,
        'unknown_subject' => $unknown,
        'openid_refused' => $openid,
    ],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
)
    . "\n");
