<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Beffroi\Core\Domain\Session\Device;
use Beffroi\Core\Domain\Session\DeviceType as DeviceKind;

/**
 * What a user agent parser said (architecture §3.5), as one JSON document on the session.
 *
 * @extends JsonObjectType<Device>
 */
final class DeviceType extends JsonObjectType
{
    public const string NAME = 'beffroi_device';

    /**
     * The document of a device, and the device of a document, for the type that nests this one
     * rather than holding it in a column of its own (`RequestContextType`): one encoding, named here, so
     * that a nested document and a column of this type cannot drift apart.
     *
     * @return array<string, mixed>|null
     */
    public function document(?Device $value): ?array
    {
        return $value === null ? null : $this->encode($value);
    }

    /**
     * @param array<array-key, mixed>|null $data
     */
    public function of(?array $data): ?Device
    {
        $value = $data === null ? null : $this->decode($data);

        return $value instanceof Device ? $value : null;
    }

    /**
     * Keyed, and said so here: the document of this type is nested in another one (`document()` above),
     * which answers for its own keys.
     *
     * @return array<string, mixed>
     */
    protected function encode(object $value): array
    {
        return [
            'type' => $value->type->value,
            'browser' => $value->browser,
            'browser_version' => $value->browserVersion,
            'platform' => $value->platform,
            'platform_version' => $value->platformVersion,
        ];
    }

    protected function decode(array $data): object
    {
        $type = DeviceKind::tryFrom($this->nullableString($data, 'type') ?? '');
        if ($type === null) {
            throw ValueNotConvertible::new($data, self::NAME, 'A device names its type.');
        }

        return new Device(
            $type,
            $this->nullableString($data, 'browser'),
            $this->nullableString($data, 'browser_version'),
            $this->nullableString($data, 'platform'),
            $this->nullableString($data, 'platform_version'),
        );
    }

    protected function expects(): string
    {
        return Device::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }
}
