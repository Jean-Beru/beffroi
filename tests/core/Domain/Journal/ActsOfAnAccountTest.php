<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Journal;

use function array_keys;
use function array_merge;
use function basename;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\PasswordRehashed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\ActsOfAnAccount;
use function class_exists;
use function dirname;
use function glob;
use function is_a;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function sort;
use function sprintf;

final class ActsOfAnAccountTest extends TestCase
{
    private const array NOT_THEIRS = [
        PasswordRehashed::NAME => 'the provider rewriting a hash it had already accepted',
    ];

    #[Test]
    public function everyActOfThePackageThatNamesAPersonIsOnTheirPageOrIsNamedAsNotTheirs(): void
    {
        // Given
        $read = array_merge(ActsOfAnAccount::NAMES, array_keys(self::NOT_THEIRS));
        sort($read);

        // When
        $declared = self::actsNamingAPerson();

        // Then
        static::assertSame($declared, $read);
    }

    /**
     * @return list<string>
     */
    private static function actsNamingAPerson(): array
    {
        $reflection = new ReflectionClass(UserAuthenticated::class);
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
            if (! class_exists($class) || ! is_a($class, ConcernsAPersonInterface::class, true)) {
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
