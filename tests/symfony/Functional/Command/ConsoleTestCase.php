<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use function preg_match;
use function preg_replace;
use function sprintf;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Architecture §7
 */
abstract class ConsoleTestCase extends BrowserTestCase
{
    /**
     * @param array<string, string|bool|list<string>|null> $input
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

    protected static function flattened(CommandTester $tester): string
    {
        return self::string(preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true)));
    }

    protected static function valueOf(CommandTester $tester): string
    {
        static::assertSame(
            1,
            preg_match('/^([A-Za-z0-9_-]{43})$/m', $tester->getDisplay(true), $matches),
            sprintf('No value was printed in: %s', $tester->getDisplay(true)),
        );

        return $matches[1];
    }

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
