<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;

/**
 * Under the ignored var/: the dump holds every personal datum of the stack.
 */
const DUMP_FILE = 'var/dump/beffroi.sql';

/**
 * In bytes: a sealed column looks random, and a shorter value turns up in a dump of some megabytes by chance.
 */
const DUMP_SHORTEST_VALUE = 5;

const DUMP_SKIPPED_TABLES = [
    'messenger_messages' => 'the message bus, which the README of the spike puts out of scope: a message carries what its handling needs for as long as its handling, and what the "failed" transport keeps is noted in the retention question and not answered here',
];

const DUMP_BACKENDS = [
    'sodium' => 'played: "castor provision --kms sodium", the default of a development stack',
    'file' => 'played: "castor provision --kms file", the self-hosted default without a KMS',
    'aws' => 'played: "castor start --kms aws" and "castor provision --kms aws", Floci',
    'vault' => 'played: "castor start --kms vault" and "castor provision --kms vault", HashiCorp Vault in dev mode',
];

/**
 * A session seals it in its provenance, so its clear form belongs nowhere in the dump.
 */
const DUMP_LABORATORY_USER_AGENT = 'Symfony HttpClient';

const DUMP_DATABASE_DEFAULTS = ['user' => 'beffroi', 'database' => 'beffroi'];

#[AsTask(
    description: 'Search a pg_dump of the running database for what the provision and the walks wrote: no personal datum appears in the clear, and a finding names the value, the table, the column and the offset',
)]
function dump_search(
    #[AsOption(description: 'Keep the dump at ' . DUMP_FILE . ' instead of removing it once searched; it holds every personal datum of the stack')]
    bool $keep = false,
): int {
    io()->title('A dump of the database gives nothing away');

    $dump = dump_take();
    $values = dump_values();
    $searched = [];
    $tooShort = [];
    foreach ($values as $value) {
        if (strlen($value) < DUMP_SHORTEST_VALUE) {
            $tooShort[] = $value;

            continue;
        }
        $searched[] = $value;
    }

    io()->definitionList(
        ['Dump' => sprintf('%s, %s', DUMP_FILE, dump_size(strlen($dump)))],
        ['Searched' => sprintf('%d value(s), as their own bytes and escaped as JSON', count($searched))],
        [
            'Skipped' => $tooShort === []
                ? 'nothing'
                : sprintf('%s, shorter than %d bytes, which a ciphertext holds by chance', implode(', ', $tooShort), DUMP_SHORTEST_VALUE),
        ],
        ['Out of scope' => implode(', ', array_keys(DUMP_SKIPPED_TABLES))],
    );

    io()->section('The backends this criterion asks for');
    io()->definitionList(...array_map(
        static fn (string $backend, string $state): array => [$backend => $state],
        array_keys(DUMP_BACKENDS),
        array_values(DUMP_BACKENDS),
    ));

    $canary = dump_canary();
    if (dump_findings($dump, [$canary]) === []) {
        io()->error(sprintf(
            'The search did not find "%s", which beffroi_tenant.issuer holds in the clear and which the model declares readable (Tenant::classifiedFields()). A search that misses what is there would miss what leaks, so this run says nothing about the dump.',
            $canary,
        ));

        return 1;
    }

    $findings = dump_findings($dump, $searched);

    if (! $keep && is_file(DUMP_FILE)) {
        unlink(DUMP_FILE);
    }

    if ($findings !== []) {
        io()->table(['Value', 'Written', 'Where', 'Offset'], $findings);
        io()->error(sprintf(
            '%d value(s) the provision or a walk wrote appear in the clear in a dump of the database, in the column named above. Two readings, and the classification the model declares decides between them (ClassifiedFieldsInterface, on the class of the field the column holds): a column it declares sealed is a leak, the mapping of its table being where the sealing type is declared and "castor console doctrine:migrations:list" saying whether the migration that seals it has run here; a column it declares readable holds those bytes legitimately, and what is wrong is then the value searched for, which collides with one of them.',
            count($findings),
        ));

        return 1;
    }

    io()->success(sprintf(
        'Nothing the provision and the walks wrote appears in the clear in a dump of the database: %d value(s) searched over %s, sealed by %s. The same search finds "%s", which the schema declares readable, so it is a search that was looking.',
        count($searched),
        dump_size(strlen($dump)),
        dump_backend(),
        $canary,
    ));

    return 0;
}

function dump_take(): string
{
    $running = compose_running_services();
    if (! in_array('database', $running, true)) {
        io()->error('The database of the stack is not running; "castor start" starts it.');

        exit(1);
    }

    if (! is_dir(dirname(DUMP_FILE)) && ! mkdir(dirname(DUMP_FILE), 0o755, true)) {
        io()->error(sprintf('The directory of %s could not be created.', DUMP_FILE));

        exit(1);
    }

    $process = run(
        ['docker', 'compose', 'exec', '-T', 'database', 'pg_dump', '-U', dump_setting('user'), '-d', dump_setting('database')],
        context: context()->withQuiet()->withAllowFailure(),
    );

    if (! $process->isSuccessful()) {
        io()->error(sprintf('pg_dump failed: %s', trim($process->getErrorOutput())));

        exit(1);
    }

    $dump = $process->getOutput();
    file_put_contents(DUMP_FILE, $dump);

    if (! str_contains($dump, 'COPY public.beffroi_user ')) {
        io()->error('The dump holds no row of beffroi_user: provision the stack and play a journey before searching it ("castor provision", then "castor demo --check").');

        exit(1);
    }

    return $dump;
}

/**
 * @return list<string>
 */
function dump_values(): array
{
    $values = [DEV_USERNAME, DEMO_PASSKEY_NAME_PREFIX, DUMP_LABORATORY_USER_AGENT];

    foreach (DEV_USER_PROFILE as $argument) {
        if (! str_starts_with($argument, '--')) {
            foreach (explode("\n", $argument) as $line) {
                $values[] = $line;
            }
        }
    }

    return array_values(array_unique(array_filter($values, static fn (string $value): bool => $value !== '')));
}

/**
 * @param list<string> $values
 *
 * @return list<array{string, string, string, string}>
 */
function dump_findings(string $dump, array $values): array
{
    $findings = [];
    $offset = 0;
    $table = null;
    $columns = [];

    foreach (explode("\n", $dump) as $line) {
        $start = $offset;
        $offset += strlen($line) + 1;

        if ($table === null) {
            if (preg_match('/^COPY (?:public\.)?(\S+) \(([^)]*)\) FROM stdin;$/', $line, $matches) === 1) {
                $table = $matches[1];
                $columns = array_map(trim(...), explode(',', $matches[2]));

                continue;
            }
        } elseif ($line === '\.') {
            $table = null;
            $columns = [];

            continue;
        }

        if ($table !== null && array_key_exists($table, DUMP_SKIPPED_TABLES)) {
            continue;
        }

        foreach ($values as $value) {
            foreach (dump_encodings($value) as $written => $needle) {
                $at = strpos($line, $needle);
                if ($at === false) {
                    continue;
                }
                $findings[] = [
                    $value,
                    $written,
                    $table === null
                        ? 'the schema of the dump, outside every COPY block'
                        : sprintf('%s.%s', $table, dump_column($line, $columns, $at)),
                    (string) ($start + $at),
                ];
            }
        }
    }

    return $findings;
}

/**
 * @param list<string> $columns
 */
function dump_column(string $line, array $columns, int $at): string
{
    $field = substr_count(substr($line, 0, $at), "\t");

    return $columns[$field] ?? sprintf('field %d, which the COPY block does not name', $field + 1);
}

/**
 * A column holding a JSON document escapes a slash, so a search for the bytes alone would miss the value there.
 *
 * @return array<string, string> the value as each encoding writes it, by the name a finding calls it
 */
function dump_encodings(string $value): array
{
    $encodings = ['as its own bytes' => $value];

    $json = json_encode($value, JSON_UNESCAPED_UNICODE);
    if ($json !== false) {
        $escaped = trim($json, '"');
        if ($escaped !== $value) {
            $encodings['escaped as JSON'] = $escaped;
        }
    }

    return $encodings;
}

function dump_backend(): string
{
    if (! is_file(DEV_ENV_LOCAL)) {
        return sprintf('a backend %s does not name, that file being absent', DEV_ENV_LOCAL);
    }

    load_dot_env(DEV_ENV_LOCAL);
    $dsn = $_SERVER['BEFFROI_KMS_DSN'] ?? '';

    return is_string($dsn) && str_contains($dsn, '://')
        ? (string) strstr($dsn, '://', true)
        : sprintf('a backend %s does not name', DEV_ENV_LOCAL);
}

/**
 * The issuer of the tenant, which names no person and is stored in the clear.
 */
function dump_canary(): string
{
    $process = run(
        [
            'docker',
            'compose',
            'exec',
            '-T',
            'database',
            'psql',
            '-U',
            dump_setting('user'),
            '-d',
            dump_setting('database'),
            '-t',
            '-A',
            '-c',
            'SELECT issuer FROM beffroi_tenant LIMIT 1',
        ],
        context: context()->withQuiet()->withAllowFailure(),
    );

    $issuer = trim($process->getOutput());
    if (! $process->isSuccessful() || $issuer === '') {
        io()->error('The issuer of the tenant could not be read, so the search has nothing to prove itself against.');

        exit(1);
    }

    return $issuer;
}

function dump_setting(string $key): string
{
    $value = $_SERVER[sprintf('POSTGRES_%s', strtoupper($key))] ?? null;

    return is_string($value) && $value !== '' ? $value : DUMP_DATABASE_DEFAULTS[$key];
}

function dump_size(int $bytes): string
{
    return sprintf('%.1f MiB', ($bytes / 1024) / 1024);
}
