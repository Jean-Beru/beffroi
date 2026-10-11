<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Command;

use Beffroi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use function preg_match;
use function preg_replace;
use function sprintf;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The commands of the bundle run on the kernel of the test, what "bin/console" does (architecture §7).
 */
abstract class ConsoleTestCase extends BrowserTestCase
{
    /**
     * Runs a command of the bundle on the kernel of the test; the inputs are the lines of the terminal, or
     * of the standard input.
     *
     * @param array<string, string|bool|list<string>> $input an option a command takes more than once is handed a list, as the console hands it one
     * @param list<string> $inputs
     */
    protected static function console(string $name, array $input = [], array $inputs = [], bool $interactive = true): CommandTester
    {
        $kernel = self::$kernel ?? static::fail('The kernel is not booted.');
        $application = new Application($kernel);
        $application->setAutoExit(false);
        $tester = new CommandTester($application->find($name));
        $tester->setInputs($inputs);
        $tester->execute($input, [
            'interactive' => $interactive,
        ]);
        self::reload();

        return $tester;
    }

    /**
     * The display as one line: what the console wrapped in a block is read as it was written.
     */
    protected static function flattened(CommandTester $tester): string
    {
        return self::string(preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true)));
    }

    /**
     * The value of a line of a definition list, as the console printed it; the first one when the display
     * holds several.
     */
    protected static function displayed(CommandTester $tester, string $label): string
    {
        $display = $tester->getDisplay(true);
        static::assertSame(
            1,
            preg_match(sprintf('/^\s*%s\s+(\S.*?)\s*$/m', $label), $display, $matches),
            sprintf('"%s" is not displayed in: %s', $label, $display),
        );

        return $matches[1];
    }
}
