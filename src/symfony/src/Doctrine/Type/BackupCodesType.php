<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use function array_is_list;
use function array_map;
use DateTimeImmutable;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Exception\InvalidType;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Doctrine\DBAL\Types\Type;
use Heidi\Core\Domain\Credential\BackupCode;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Exception\InvalidArgumentException;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use JsonException;

/**
 * The backup codes of a TOTP as a JSON list, in their order: each one the hash of the code, typed by its
 * algorithm like a password hash with the parameters of an import, and the Unix timestamp it was spent at.
 */
final class BackupCodesType extends Type
{
    public const string NAME = 'heidi_backup_codes';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_array($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'list<' . BackupCode::class . '>']);
        }
        $entries = [];
        foreach ($value as $code) {
            if (! $code instanceof BackupCode) {
                throw InvalidType::new($value, self::NAME, ['null', 'list<' . BackupCode::class . '>']);
            }
            $entries[] = [
                'algorithm' => $code->hash->algorithm->value,
                'encoded' => $code->hash->encoded,
                'parameters' => $code->hash->parameters,
                'used_at' => $code->usedAt?->getTimestamp(),
            ];
        }

        try {
            return json_encode($entries, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
    }

    /**
     * @return list<BackupCode>|null
     */
    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?array
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw InvalidType::new($value, self::NAME, ['null', 'string']);
        }

        try {
            $decoded = json_decode($value, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw ValueNotConvertible::new($value, self::NAME, $exception->getMessage(), $exception);
        }
        if (! is_array($decoded) || ! array_is_list($decoded)) {
            throw ValueNotConvertible::new($value, self::NAME, 'A JSON list was expected.');
        }

        return array_map(fn (mixed $entry): BackupCode => $this->entry($value, $entry), $decoded);
    }

    private function entry(string $document, mixed $entry): BackupCode
    {
        $algorithm = is_array($entry) && is_string($entry['algorithm'] ?? null) ? PasswordAlgorithm::tryFrom($entry['algorithm']) : null;
        $encoded = is_array($entry) ? ($entry['encoded'] ?? null) : null;
        $parameters = is_array($entry) ? ($entry['parameters'] ?? []) : null;
        $usedAt = is_array($entry) ? ($entry['used_at'] ?? null) : null;
        if ($algorithm === null || ! is_string($encoded) || ! is_array($parameters) || ($usedAt !== null && ! is_int($usedAt))) {
            throw ValueNotConvertible::new($document, self::NAME, 'A backup code is a typed hash and the Unix timestamp it was spent at.');
        }
        $typed = [];
        foreach ($parameters as $name => $parameter) {
            if (! is_string($name) || (! is_int($parameter) && ! is_string($parameter))) {
                throw ValueNotConvertible::new($document, self::NAME, 'The parameters of a hash are strings or integers by name.');
            }
            $typed[$name] = $parameter;
        }

        try {
            return new BackupCode(new PasswordHash($algorithm, $encoded, $typed), $usedAt === null ? null : new DateTimeImmutable('@' . $usedAt));
        } catch (InvalidArgumentException $exception) {
            throw ValueNotConvertible::new($document, self::NAME, $exception->getMessage(), $exception);
        }
    }
}
