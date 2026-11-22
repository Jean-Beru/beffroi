<?php

declare(strict_types=1);

/*
 * The client of "castor demo --attested": a registration authorised by a software statement (RFC 7591 §2.3).
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

final readonly class AttestationAuthority
{
    private const string ALGORITHM = 'ES256';

    private JWSBuilder $jws;

    private CompactSerializer $serializer;

    public function __construct(
        private JWK $key,
        private string $issuer,
    ) {
        $this->jws = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * RFC 7591 §2.3
     *
     * @param array<string, mixed> $members
     *
     * @return array{0: string, 1: array<string, mixed>} the compact JWS and the claims it carries
     */
    public function sign(string $audience, array $members, int $lifetime = 60): array
    {
        $now = time();
        $claims = [
            'iss' => $this->issuer,
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + $lifetime,
            // Drawn, never counted: nobody else may produce an identifier the replay guard remembers.
            'jti' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
            ...$members,
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

        return [$this->serializer->serialize($jws, 0), $claims];
    }
}

/**
 * RFC 7591 §3.1
 */
final readonly class AttestedClient
{
    private HttpClientInterface $http;

    public function __construct(
        string $cafile,
        private string $endpoint,
    ) {
        $this->http = HttpClient::create([
            'max_redirects' => 0,
            'cafile' => $cafile,
        ]);
    }

    /**
     * @param array<string, mixed> $metadata
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function register(array $metadata, ?string $statement): array
    {
        if ($statement !== null) {
            $metadata['software_statement'] = $statement;
        }

        try {
            $response = $this->http->request('POST', $this->endpoint, [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => json_encode($metadata, JSON_THROW_ON_ERROR),
            ]);
            $status = $response->getStatusCode();
            $body = json_decode($response->getContent(false), true, 8, JSON_THROW_ON_ERROR);
        } catch (HttpExceptionInterface $exception) {
            return [
                'status' => 0,
                'body' => ['error' => $exception->getMessage()],
            ];
        }

        return [
            'status' => $status,
            'body' => is_array($body) ? attestation_cli_named($body) : [],
        ];
    }
}

/**
 * @param array<array-key, mixed> $decoded
 *
 * @return array<string, mixed>
 */
function attestation_cli_named(array $decoded): array
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
function attestation_cli_text(array $input, string $name): string
{
    $value = $input[$name] ?? null;

    return is_string($value) && $value !== '' ? $value : throw new RuntimeException(sprintf('The input carries no "%s".', $name));
}

/**
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function attestation_cli_object(array $input, string $name): array
{
    $value = $input[$name] ?? null;

    return is_array($value) ? attestation_cli_named($value) : throw new RuntimeException(sprintf('The input carries no "%s" object.', $name));
}

function attestation_cli_key(string $file): JWK
{
    $set = json_decode((string) file_get_contents($file), true, 8, JSON_THROW_ON_ERROR);
    $keys = is_array($set) && is_array($set['keys'] ?? null) ? $set['keys'] : [];

    return is_array($keys[0] ?? null) ? new JWK($keys[0]) : throw new RuntimeException(sprintf('%s carries no key.', $file));
}

$read = json_decode((string) file_get_contents('php://stdin'), true, 16, JSON_THROW_ON_ERROR);
if (! is_array($read)) {
    throw new RuntimeException('This program reads one JSON object on its standard input.');
}
$input = attestation_cli_named($read);
$audience = attestation_cli_text($input, 'audience');
$authority = new AttestationAuthority(
    attestation_cli_key(attestation_cli_text($input, 'jwks_file')),
    attestation_cli_text($input, 'authority'),
);
// The issuer of "castor demo --assertion": pinned by this tenant for users, never for software (RFC 7591 §2.3).
$stranger = new AttestationAuthority(
    attestation_cli_key(attestation_cli_text($input, 'stranger_jwks_file')),
    attestation_cli_text($input, 'stranger_authority'),
);
$client = new AttestedClient(attestation_cli_text($input, 'cafile'), attestation_cli_text($input, 'registration_endpoint'));
$metadata = attestation_cli_object($input, 'metadata');
$attested = attestation_cli_object($input, 'attested');

[$statement, $claims] = $authority->sign($audience, $attested);
$registered = $client->register($metadata, $statement);
$replayed = $client->register($metadata, $statement);
[$signedByAStranger] = $stranger->sign($audience, $attested);
[$addressedElsewhere] = $authority->sign(attestation_cli_text($input, 'elsewhere'), $attested);

fwrite(STDOUT, json_encode(
    [
        'statement' => $claims,
        'registered' => $registered,
        'replayed' => $replayed,
        'stranger' => $client->register($metadata, $signedByAStranger),
        'elsewhere' => $client->register($metadata, $addressedElsewhere),
        'without_statement' => $client->register($metadata, null),
    ],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
)
    . "\n");
