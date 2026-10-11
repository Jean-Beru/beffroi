<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Application\Credential\StoredPasswordHash;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use LogicException;

/**
 * A stored password hash of a credential, in the one document the core writes a hash as
 * (`StoredPasswordHash`): the algorithm it was made with by the name it carries (decision 0002), the
 * encoded form, and the parameters an import keeps apart from the digest.
 *
 * The handoff through a static is the Doctrine half: Doctrine builds a type from a class name, so nothing
 * can be injected here; what reads the document takes the wiring as an argument, and this hands it the one
 * the bundle gave it when it booted.
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
        return self::hashes()->document($value);
    }

    protected function decode(array $data): object
    {
        return self::hashes()->of($data);
    }

    protected function expects(): string
    {
        return PasswordHash::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    private static function hashes(): StoredPasswordHash
    {
        return new StoredPasswordHash(
            self::$algorithms ?? throw new LogicException('The password algorithms have not been handed to the DBAL type; the bundle does it when it boots.'),
        );
    }
}
