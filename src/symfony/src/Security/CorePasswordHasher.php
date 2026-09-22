<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\ExceptionInterface;
use Heidi\Core\Port\PasswordHasherInterface as CoreHasher;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use SensitiveParameter;
use Symfony\Component\PasswordHasher\Exception\InvalidPasswordException;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

/**
 * The password hasher of Symfony bridged to the hasher of the core (architecture §5.4). The string the
 * component sees is the JSON of a typed hash (decision 0002), written and read here only.
 */
final readonly class CorePasswordHasher implements PasswordHasherInterface
{
    public function __construct(
        private CoreHasher $hasher,
    ) {
    }

    public function hash(#[SensitiveParameter] string $plainPassword): string
    {
        try {
            return self::encode($this->hasher->hash($plainPassword));
        } catch (ExceptionInterface $exception) {
            throw new InvalidPasswordException($exception->getMessage(), 0, $exception);
        }
    }

    public function verify(string $hashedPassword, #[SensitiveParameter] string $plainPassword): bool
    {
        $hash = self::decode($hashedPassword);
        if ($hash === null) {
            return false;
        }
        try {
            return $this->hasher->verify($hash, $plainPassword);
        } catch (ExceptionInterface) {
            return false;
        }
    }

    public function needsRehash(string $hashedPassword): bool
    {
        $hash = self::decode($hashedPassword);
        if ($hash === null) {
            return false;
        }
        try {
            return $this->hasher->needsRehash($hash);
        } catch (ExceptionInterface) {
            return false;
        }
    }

    public static function encode(PasswordHash $hash): string
    {
        return json_encode([
            'algorithm' => $hash->algorithm->value,
            'encoded' => $hash->encoded,
            'parameters' => $hash->parameters,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Null when the string is not one encode() wrote; no algorithm is guessed.
     */
    public static function decode(string $encoded): ?PasswordHash
    {
        try {
            $decoded = json_decode($encoded, true, 3, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        if (! is_array($decoded)) {
            return null;
        }
        $algorithm = is_string($decoded['algorithm'] ?? null) ? PasswordAlgorithm::tryFrom($decoded['algorithm']) : null;
        $hash = $decoded['encoded'] ?? null;
        $parameters = $decoded['parameters'] ?? [];
        if ($algorithm === null || ! is_string($hash) || $hash === '' || ! is_array($parameters)) {
            return null;
        }
        $validated = [];
        foreach ($parameters as $name => $value) {
            if (! is_string($name) || ! is_int($value) && ! is_string($value)) {
                return null;
            }
            $validated[$name] = $value;
        }

        return new PasswordHash($algorithm, $hash, $validated);
    }
}
