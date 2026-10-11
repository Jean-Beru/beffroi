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

/**
 * Issue #571: which acts of the journal are what happened to an account, the question the page of a person
 * asks of their own journal.
 *
 * An act of this package that names a person is read by that person on that page, so the list is held to
 * the events by a walk of them and not by a comment: an act added here is on the page, or is named below
 * as one that is not theirs to read, and the mapping that would be wrong is the one nobody edited.
 */
final class ActsOfAnAccountTest extends TestCase
{
    /**
     * The one act of this package that names a person and is not what happened to their account: this
     * provider storing the same password under a stronger hash, which is a decision of the deployment
     * about its own hashing and nothing the person did or would recognise (PasswordChanged is the act of
     * the person). It is in the journal and in the archive all the same, where it answers a question an
     * operator asks.
     */
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
     * The name of an act is the one the event gives itself, which is what the journal writes down: a list
     * holding a name no event answers to is a filter that reads nothing.
     *
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
            // an act is a class: the interface that says a person is named is not one of them
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
