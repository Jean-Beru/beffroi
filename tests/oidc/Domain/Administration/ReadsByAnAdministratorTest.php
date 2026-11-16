<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Administration;

use function basename;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;
use Beffroi\Oidc\Domain\Administration\ReadsByAnAdministrator;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use function class_exists;
use function dirname;
use function glob;
use function is_a;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function sort;
use function sprintf;

final class ReadsByAnAdministratorTest extends TestCase
{
    /**
     * Decisions 0022 and 0038
     */
    #[Test]
    public function everyActOfThePackageThatNamesAnAdministratorIsAReadThePageOfThePersonLists(): void
    {
        // Given
        $listed = ReadsByAnAdministrator::NAMES;
        sort($listed);

        // When
        $named = self::actsNamingTheirAuthor();

        // Then
        static::assertSame($named, $listed);
    }

    /**
     * @return list<string>
     */
    private static function actsNamingTheirAuthor(): array
    {
        $reflection = new ReflectionClass(TokensIssued::class);
        $file = $reflection->getFileName();
        if ($file === false) {
            static::fail('The events of the package are read from the directory of one of them.');
        }
        $files = glob(dirname($file) . '/*.php');
        if ($files === false) {
            static::fail(sprintf('The directory of the events cannot be read: %s.', dirname($file)));
        }
        $named = [];
        foreach ($files as $candidate) {
            /** @var class-string $class */
            $class = $reflection->getNamespaceName() . '\\' . basename($candidate, '.php');
            if (! class_exists($class) || ! is_a($class, NamesItsAuthorInterface::class, true)) {
                continue;
            }
            $name = new ReflectionClass($class)->getConstant('NAME');
            static::assertIsString($name, sprintf('The act "%s" gives itself no name.', $class));
            $named[] = $name;
        }
        sort($named);

        return $named;
    }
}
