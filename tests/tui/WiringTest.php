<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests;

use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Text\TerminalLocale;
use Beffroi\Tui\Wiring;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_contains;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use function sys_get_temp_dir;
use function uniqid;

/**
 * The program as it is put together.
 */
final class WiringTest extends TestCase
{
    #[Test]
    public function everySectionIsNamedInEveryLanguage(): void
    {
        // Given
        $missing = [];

        // When
        foreach (TerminalLocale::SUPPORTED as $locale) {
            $translator = Catalogue::translator($locale);
            foreach (Wiring::sections() as $section) {
                if ($translator->trans($section->title(), domain: Catalogue::DOMAIN) === $section->title()) {
                    $missing[] = $locale . ':' . $section->title();
                }
            }
        }

        // Then
        static::assertSame([], $missing);
    }

    #[Test]
    public function theAdministrationIsWhatTheProgramOpensWithoutACommand(): void
    {
        // Given
        $application = Wiring::application(['HOME' => sprintf('%s/beffroi-tui-%s', sys_get_temp_dir(), uniqid())]);
        $application->setAutoExit(false);
        $output = new BufferedOutput();

        // When
        $status = $application->run(new ArrayInput([]), $output);

        // Then
        static::assertSame([1, true], [$status, str_contains($output->fetch(), 'There is no profile "default"')]);
    }
}
