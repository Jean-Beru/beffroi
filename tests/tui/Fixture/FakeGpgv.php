<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use function chmod;
use function escapeshellarg;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function implode;
use function mkdir;
use function rtrim;
use function sprintf;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function rmdir;

/**
 * A `gpgv` that writes the status lines it is given to its status descriptor, ends with the status given, and
 * keeps the arguments it was called with: what the verifier makes of an answer of gpgv, on a machine that has no
 * GnuPG.
 */
final readonly class FakeGpgv
{
    private function __construct(
        public string $directory,
    ) {
    }

    /**
     * @param list<string> $status the lines written to the status descriptor, without their `[GNUPG:] ` prefix
     */
    public static function answering(array $status, int $exit): self
    {
        $directory = sprintf('%s/beffroi-tui-gpgv-%s', sys_get_temp_dir(), uniqid());
        mkdir($directory);
        $lines = '';
        foreach ($status as $line) {
            $lines .= sprintf("printf '%%s\\n' %s\n", escapeshellarg('[GNUPG:] ' . $line));
        }
        file_put_contents($directory . '/gpgv', sprintf(
            "#!/bin/sh\nfor argument in \"\$@\"; do printf '%%s\\n' \"\$argument\"; done > %s\n%sexit %d\n",
            escapeshellarg($directory . '/arguments'),
            $lines,
            $exit,
        ));
        chmod($directory . '/gpgv', 0o755);

        return new self($directory);
    }

    /**
     * @return list<string>
     */
    public function arguments(): array
    {
        return explode("\n", rtrim((string) file_get_contents($this->directory . '/arguments'), "\n"));
    }

    public function remove(): void
    {
        @unlink($this->directory . '/arguments');
        @unlink($this->directory . '/gpgv');
        @rmdir($this->directory);
    }

    /**
     * A `VALIDSIG` line of a signature made by the key given, under the primary key given (GnuPG, doc/DETAILS).
     */
    public static function validSignature(string $signingKey, string $primaryKey): string
    {
        return implode(' ', ['VALIDSIG', $signingKey, '2026-11-22', '1795383807', '0', '4', '0', '1', '10', '00', $primaryKey]);
    }
}
