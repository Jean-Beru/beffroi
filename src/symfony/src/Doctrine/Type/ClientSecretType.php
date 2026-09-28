<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Heidi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\PasswordAlgorithmsInterface;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use function is_array;
use function is_int;
use function is_string;
use LogicException;

/**
 * The secret the provider handed a client that registered itself, in the one column that keeps it
 * (RFC 7591 §3.2.1). One column, so that the day a deployment encrypts it at rest is the day one column
 * changes and nothing else (spike 8).
 *
 * A secret is kept in one of the two shapes the domain has, and the row says which: the digest of a
 * secret the provider cannot read back, which is what a method that receives one verifies against
 * (RFC 6749 §2.3.1), or the secret itself, which is what a method that signs with it needs
 * (OIDC Core §9, "client_secret_jwt"). The two are not an open set the wiring decides, as the kinds of
 * confirmation are: either the provider can compute what the client computed, or it cannot. A hash names
 * the algorithm it was made with and is read back as the class the wiring holds for that name, exactly as
 * the hash of a password is (decision 0002).
 *
 * @extends JsonObjectType<ClientSecretInterface>
 */
final class ClientSecretType extends JsonObjectType implements NeedsPasswordAlgorithmsInterface
{
    public const string NAME = 'heidi_client_secret';

    private const string HASH = 'hash';

    private const string SHARED = 'shared';

    private const string ALGORITHM = 'algorithm';

    private const string ENCODED = 'encoded';

    private const string PARAMETERS = 'parameters';

    private static ?PasswordAlgorithmsInterface $algorithms = null;

    public static function resolveWith(PasswordAlgorithmsInterface $algorithms): void
    {
        self::$algorithms = $algorithms;
    }

    protected function encode(object $value): array
    {
        if ($value instanceof SharedClientSecret) {
            return [
                self::SHARED => $value->value,
            ];
        }

        if (! $value instanceof HashedClientSecret) {
            throw InvalidType::new($value, self::NAME, [SharedClientSecret::class, HashedClientSecret::class]);
        }
        $hash = $value->hash;

        return [
            self::HASH => [
                self::ALGORITHM => $hash->algorithm->name(),
                self::ENCODED => $hash->encoded,
                self::PARAMETERS => $hash->parameters,
            ],
        ];
    }

    protected function decode(array $data): object
    {
        $shared = $data[self::SHARED] ?? null;
        if (is_string($shared)) {
            return new SharedClientSecret($shared);
        }
        $hash = $data[self::HASH] ?? null;
        if (! is_array($hash)) {
            throw ValueNotConvertible::new($data, self::NAME, 'A stored client secret carries a "hash" or a "shared" member.');
        }

        $encoded = $hash[self::ENCODED] ?? null;
        if (! is_string($encoded)) {
            throw ValueNotConvertible::new($data, self::NAME, 'A stored client secret hash carries its encoded form.');
        }

        return new HashedClientSecret(new PasswordHash($this->algorithm($hash), $encoded, $this->parameters($hash)));
    }

    protected function expects(): string
    {
        return ClientSecretInterface::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    /**
     * @param array<array-key, mixed> $hash
     */
    private function algorithm(array $hash): PasswordAlgorithmInterface
    {
        $algorithms =
            self::$algorithms ?? throw new LogicException('The password algorithms have not been handed to the DBAL type; the bundle does it when it boots.');
        $name = $hash[self::ALGORITHM] ?? null;
        if (! is_string($name)) {
            throw ValueNotConvertible::new($hash, self::NAME, 'A stored client secret hash names the algorithm it was made with.');
        }

        try {
            return $algorithms->named($name);
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidArgumentException($exception->getMessage(), 0, $exception);
        }
    }

    /**
     * What an imported format keeps apart from the digest, as the hash of a password does.
     *
     * @param array<array-key, mixed> $hash
     *
     * @return array<string, int|string>
     */
    private function parameters(array $hash): array
    {
        $parameters = $hash[self::PARAMETERS] ?? [];
        if (! is_array($parameters)) {
            throw ValueNotConvertible::new($hash, self::NAME, 'The parameters of a stored client secret hash are an object.');
        }
        $kept = [];
        foreach ($parameters as $name => $value) {
            if (! is_string($name) || ! is_string($value) && ! is_int($value)) {
                throw ValueNotConvertible::new($hash, self::NAME, 'The parameters of a stored client secret hash are named, and each is a string or a number.');
            }
            $kept[$name] = $value;
        }

        return $kept;
    }
}
