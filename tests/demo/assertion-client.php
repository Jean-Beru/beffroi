<?php

declare(strict_types=1);

/*
 * The client of "castor demo --assertion": assertions of a trusted issuer exchanged for tokens (RFC 7523 §2.1).
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
 * RFC 7523 §3
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
     * RFC 7523 §3
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
            // Drawn, never counted: nobody else may produce an identifier the replay guard remembers.
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
 * RFC 7523 §2.1
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
     * Decoded only to report its RFC 9068 §2.2 claims: a client verifies nothing of a token it merely carries.
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
