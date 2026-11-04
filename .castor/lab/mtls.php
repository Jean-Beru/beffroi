<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

const MTLS_PATH = '/mtls/client-certificate';

const MTLS_FORGED_HEADER = 'X-Client-Cert';

const MTLS_CA_FILE = 'var/caddy-root.crt';

#[AsTask(
    description: 'Measure the client certificate at the edge (issue #157): present the certificate of "castor provision" to the listener that asks for one, compare the thumbprint the application computes with the one computed here, check that the same request without a certificate is served all the same, that the ordinary host of the OP asks for nothing and reads nothing, and that a certificate carried in a header is refused',
)]
function mtls(
    #[AsOption(description: 'The host of the listener that asks for a client certificate; MTLS_SERVER_NAME of compose.yaml')]
    string $host = DEV_MTLS_SERVER_NAME,
    #[AsOption(description: 'The ordinary host of the OP, the one that must stay untouched')]
    string $ordinaryHost = 'op.localhost',
): void {
    io()->title('The client certificate from the edge to PHP');

    $directory = getcwd() . '/' . DEV_MTLS_DIRECTORY;
    $certificateFile = $directory . '/client.crt';
    $keyFile = $directory . '/client.key';
    if (! is_file($certificateFile) || ! is_file($keyFile)) {
        io()->error(sprintf('%s holds no client certificate: run "castor provision" first.', DEV_MTLS_DIRECTORY));
        exit(1);
    }
    $expected = mtls_thumbprint((string) file_get_contents($certificateFile));
    $ca = caddy_ca(getcwd() . '/' . MTLS_CA_FILE);
    $client = ['--cert', $certificateFile, '--key', $keyFile];
    $measured = [];

    io()->section(sprintf('https://%s, the listener that asks for a certificate', $host));

    [$status, $answer] = mtls_get($host, $ca, $client);
    mtls_expect($status === 200 && ($answer['client_certificate'] ?? null) === 'present', sprintf(
        'the certificate presented at the handshake reaches PHP (got %d %s)',
        $status,
        json_encode($answer),
    ));
    mtls_expect(($answer['x5t#S256'] ?? null) === $expected, sprintf(
        'what reached PHP is the certificate that was presented: the application computes %s, this task computes %s',
        $answer['x5t#S256'] ?? '?',
        $expected,
    ));
    $measured[] = ['Certificate presented', sprintf('200, %d bytes of DER, x5t#S256 %s', $answer['der_bytes'] ?? 0, $expected)];

    [$status, $answer] = mtls_get($host, $ca, []);
    mtls_expect($status === 200 && ($answer['client_certificate'] ?? null) === 'absent', sprintf(
        'a request without a certificate is served on the same path and says so, rather than failing at the handshake (got %d %s)',
        $status,
        json_encode($answer),
    ));
    $measured[] = ['No certificate presented', '200, "absent": the listener asks, it does not require'];

    [$status, $answer] = mtls_get($host, $ca, $client, [MTLS_FORGED_HEADER]);
    mtls_expect($status === 400 && ($answer['client_certificate'] ?? null) === 'refused', sprintf(
        'a request carrying a certificate in the "%s" header is refused, even while presenting a real one at the handshake (got %d %s)',
        MTLS_FORGED_HEADER,
        $status,
        json_encode($answer),
    ));
    $measured[] = [sprintf('"%s" header', MTLS_FORGED_HEADER), '400, "refused": nothing in front of the application sets it'];

    io()->section(sprintf('https://%s, the ordinary host, which must not have changed', $ordinaryHost));

    [$status, $answer] = mtls_get($ordinaryHost, $ca, $client);
    mtls_expect($status === 200 && ($answer['client_certificate'] ?? null) === 'absent', sprintf(
        'the ordinary host asks for no certificate, and reads none from a client that offers one anyway (got %d %s)',
        $status,
        json_encode($answer),
    ));
    $measured[] = ['Ordinary host, certificate offered', '200, "absent": the variable exists only where the listener sets it'];

    [$status, $answer] = mtls_get($ordinaryHost, $ca, [], [MTLS_FORGED_HEADER]);
    mtls_expect($status === 400 && ($answer['client_certificate'] ?? null) === 'refused', sprintf(
        'the same forged header is refused there too (got %d %s)',
        $status,
        json_encode($answer),
    ));
    $measured[] = [sprintf('Ordinary host, "%s" header', MTLS_FORGED_HEADER), '400, "refused"'];

    [$status] = mtls_get($ordinaryHost, $ca, [], [], '/.well-known/openid-configuration');
    mtls_expect($status === 200, sprintf(
        'the ordinary host still serves the discovery document, the second listener having changed nothing of it (got %d)',
        $status,
    ));
    $measured[] = ['Ordinary host, discovery', '200: the six certification plans run against this one'];

    io()->table(['Measured', 'Result'], $measured);
    io()->success(sprintf(
        'The client certificate crosses Caddy and FrankenPHP and reaches PHP as the leaf in a PEM envelope, in the SSL_CLIENT_CERT variable of the mTLS site block, and nowhere else. Thumbprint %s.',
        $expected,
    ));
    io()->note('The chain is not handed over, only the leaf: what has to be validated against a certificate authority is validated at the edge, with a "trust_pool" in apps/op/frankenphp/mtls.Caddyfile, never in PHP (architecture §6, §7).');
}

/**
 * With curl: no HTTP client of the toolbox presents a client certificate.
 *
 * @param list<string> $client  the "--cert" and "--key" of a client that presents one, empty otherwise
 * @param list<string> $headers the headers to carry, each given the PEM of the certificate as its value
 *
 * @return array{0: int, 1: array<string, mixed>}
 */
function mtls_get(string $host, string $ca, array $client, array $headers = [], string $path = MTLS_PATH): array
{
    $forged = [];
    foreach ($headers as $header) {
        $forged[] = '-H';
        $forged[] = $header . ': ' . mtls_one_line((string) file_get_contents(getcwd() . '/' . DEV_MTLS_DIRECTORY . '/client.crt'));
    }
    $curl = run([
        'curl',
        '--silent',
        '--show-error',
        '--cacert',
        $ca,
        '--write-out',
        "\n%{http_code}",
        ...$client,
        ...$forged,
        sprintf('https://%s%s', $host, $path),
    ], context: context()->withQuiet()->withAllowFailure());
    if (! $curl->isSuccessful()) {
        io()->error(sprintf('curl could not reach https://%s%s: %s', $host, $path, trim($curl->getErrorOutput())));
        exit(1);
    }
    $output = $curl->getOutput();
    $separator = strrpos($output, "\n");
    $status = (int) substr($output, $separator === false ? 0 : $separator + 1);
    $body = json_decode($separator === false ? '' : substr($output, 0, $separator), true);

    return [$status, is_array($body) ? $body : []];
}

function mtls_one_line(string $pem): string
{
    return (string) preg_replace('/\s+/', ' ', trim($pem));
}

function mtls_expect(bool $condition, string $what): void
{
    if (! $condition) {
        io()->error('Not measured: ' . $what);
        exit(1);
    }
    io()->text(' <info>✓</info> ' . $what);
}
