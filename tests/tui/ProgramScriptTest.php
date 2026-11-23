<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests;

use function dirname;
use function file_put_contents;
use function mkdir;
use const PHP_BINARY;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function rmdir;
use function sprintf;
use Symfony\Component\Process\Process;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function var_export;

/**
 * `bin/beffroi-tui` finds the autoloader of the installation it runs in: the one the proxy of Composer names in
 * `vendor/bin/` when the program is a dependency, and the monorepo's when it runs from it.
 */
final class ProgramScriptTest extends TestCase
{
    private const string SCRIPT = __DIR__ . '/../../apps/tui/bin/beffroi-tui';

    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sprintf('%s/beffroi-tui-script-%s', sys_get_temp_dir(), uniqid());
        mkdir($this->directory, 0o700);
    }

    protected function tearDown(): void
    {
        @unlink($this->directory . '/autoload.php');
        @unlink($this->directory . '/beffroi-tui');
        @rmdir($this->directory);
    }

    #[Test]
    public function theScriptTakesTheAutoloaderTheProxyOfComposerNames(): void
    {
        // Given
        $autoloader = $this->directory . '/autoload.php';
        file_put_contents($autoloader, "<?php\necho 'the autoloader of the installation';\nexit(0);\n");
        $proxy = $this->directory . '/beffroi-tui';
        file_put_contents($proxy, sprintf(
            "<?php\n\$GLOBALS['_composer_autoload_path'] = %s;\n\nreturn include %s;\n",
            var_export($autoloader, true),
            var_export(self::SCRIPT, true),
        ));

        // When
        $run = $this->started([PHP_BINARY, $proxy]);

        // Then
        static::assertSame([0, 'the autoloader of the installation'], [$run->getExitCode(), $run->getOutput()]);
    }

    #[Test]
    public function theScriptRunFromTheMonorepoTakesItsAutoloader(): void
    {
        // When
        $run = $this->started([PHP_BINARY, self::SCRIPT, 'list', '--raw']);

        // Then
        static::assertSame([0, 1], [$run->getExitCode(), preg_match('/^self-update /m', $run->getOutput())]);
    }

    /**
     * @param list<string> $command
     */
    private function started(array $command): Process
    {
        // the suite makes every console quiet (SHELL_VERBOSITY=-1), which a process started from it inherits
        $process = new Process($command, dirname(self::SCRIPT), ['XDG_CONFIG_HOME' => $this->directory, 'SHELL_VERBOSITY' => false], null, 30);
        $process->run();

        return $process;
    }
}
