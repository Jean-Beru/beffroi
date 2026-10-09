<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use function is_array;
use function is_int;
use function is_string;
use LogicException;

/**
 * A stored password hash of a credential: the algorithm it was made with, by the name it carries (decision
 * 0002), the encoded form, and the parameters an import keeps apart from the digest.
 *
 * The algorithm is read back as the class the wiring holds for that name, as `PasswordAlgorithmType` does
 * for a column that carries nothing else: a name nothing wired accounts for is a row this deployment
 * cannot read, and it says so at load rather than handing back an algorithm nobody chose.
 *
 * @extends JsonObjectType<PasswordHash>
 */
final class PasswordHashType extends JsonObjectType implements NeedsPasswordAlgorithmsInterface
{
    public const string NAME = 'beffroi_password_hash';

    private static ?PasswordAlgorithmsInterface $algorithms = null;

    public static function resolveWith(PasswordAlgorithmsInterface $algorithms): void
    {
        self::$algorithms = $algorithms;
    }

    protected function encode(object $value): array
    {
        return [
            'algorithm' => $value->algorithm->name(),
            'encoded' => $value->encoded,
            'parameters' => $value->parameters,
        ];
    }

    protected function decode(array $data): object
    {
        $algorithm = $data['algorithm'] ?? null;
        $encoded = $data['encoded'] ?? null;
        $parameters = $data['parameters'] ?? [];
        if (! is_string($algorithm) || ! is_string($encoded) || ! is_array($parameters)) {
            throw ValueNotConvertible::new(
                $data,
                self::NAME,
                'A password hash names its algorithm and carries its encoded form.',
            );
        }

        $kept = [];
        foreach ($parameters as $name => $parameter) {
            if (! is_string($name) || (! is_int($parameter) && ! is_string($parameter))) {
                throw ValueNotConvertible::new(
                    $data,
                    self::NAME,
                    'The parameters of a password hash map a name to a number or a string.',
                );
            }
            $kept[$name] = $parameter;
        }

        $algorithms =
            self::$algorithms ?? throw new LogicException('The password algorithms have not been handed to the DBAL type; the bundle does it when it boots.');

        try {
            return new PasswordHash($algorithms->named($algorithm), $encoded, $kept);
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidArgumentException($exception->getMessage(), 0, $exception);
        }
    }

    protected function expects(): string
    {
        return PasswordHash::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
