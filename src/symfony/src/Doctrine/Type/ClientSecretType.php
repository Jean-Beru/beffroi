<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Oidc\Application\Client\StoredClientSecret;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use LogicException;

/**
 * The secret the provider handed a client that registered itself, in the one column that keeps it
 * (RFC 7591 §3.2.1). One column, so that the day a deployment encrypts it at rest is the day one column
 * changes and nothing else (spike 8). What the document holds, and which of the two shapes of a secret it
 * says, is the module's own (`StoredClientSecret`).
 *
 * The handoff through a static is the Doctrine half: Doctrine builds a type from a class name, so nothing
 * can be injected here; what reads the document takes the wiring as an argument, and this hands it the one
 * the bundle gave it when it booted.
 *
 * @extends JsonObjectType<ClientSecretInterface>
 */
final class ClientSecretType extends JsonObjectType implements NeedsPasswordAlgorithmsInterface
{
    public const string NAME = 'beffroi_client_secret';

    private static ?PasswordAlgorithmsInterface $algorithms = null;

    public static function resolveWith(PasswordAlgorithmsInterface $algorithms): void
    {
        self::$algorithms = $algorithms;
    }

    protected function encode(object $value): array
    {
        return self::secrets()->document($value);
    }

    protected function decode(array $data): object
    {
        return self::secrets()->of($data);
    }

    protected function expects(): string
    {
        return ClientSecretInterface::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    private static function secrets(): StoredClientSecret
    {
        return new StoredClientSecret(
            self::$algorithms ?? throw new LogicException('The password algorithms have not been handed to the DBAL type; the bundle does it when it boots.'),
        );
    }
}
