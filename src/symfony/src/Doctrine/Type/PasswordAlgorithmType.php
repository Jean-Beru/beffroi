<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Heidi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\PasswordAlgorithmsInterface;
use LogicException;

/**
 * The algorithm a stored password hash was made with, kept as the name it carries (decision 0002) and
 * read back as the class the wiring holds for that name. A name nothing wired accounts for is a row this
 * deployment cannot read, and it says so at load instead of handing back an algorithm nobody chose.
 *
 * @extends StringObjectType<PasswordAlgorithmInterface>
 */
final class PasswordAlgorithmType extends StringObjectType implements NeedsPasswordAlgorithmsInterface
{
    public const string NAME = 'heidi_password_algorithm';

    private static ?PasswordAlgorithmsInterface $algorithms = null;

    public static function resolveWith(PasswordAlgorithmsInterface $algorithms): void
    {
        self::$algorithms = $algorithms;
    }

    protected function encode(object $value): string
    {
        return $value->name();
    }

    protected function decode(string $value): object
    {
        $algorithms =
            self::$algorithms ?? throw new LogicException('The password algorithms have not been handed to the DBAL type; the bundle does it when it boots.');

        try {
            return $algorithms->named($value);
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidArgumentException($exception->getMessage(), 0, $exception);
        }
    }

    protected function expects(): string
    {
        return PasswordAlgorithmInterface::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
