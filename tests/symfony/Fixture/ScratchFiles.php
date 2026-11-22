<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use function file_get_contents;
use function file_put_contents;
use LogicException;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * Files the openssl extension reads and writes by name, removed once the test is done with them.
 */
final class ScratchFiles
{
    /**
     * @var list<string>
     */
    private array $paths = [];

    public function holding(string $content = ''): string
    {
        $path = tempnam(sys_get_temp_dir(), 'scratch');
        if ($path === false || file_put_contents($path, $content) === false) {
            throw new LogicException('No scratch file can be written.');
        }
        $this->paths[] = $path;

        return $path;
    }

    public static function read(string $path): string
    {
        $content = file_get_contents($path);
        if ($content === false) {
            throw new LogicException('The scratch file cannot be read.');
        }

        return $content;
    }

    public function __destruct()
    {
        foreach ($this->paths as $path) {
            @unlink($path);
        }
    }
}
