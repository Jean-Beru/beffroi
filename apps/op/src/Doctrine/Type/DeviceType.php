<?php

declare(strict_types=1);

namespace App\Doctrine\Type;

use Beffroi\Core\Domain\Session\Device;

/**
 * What a user agent parser said (architecture §3.5), as one JSON column. What the document holds is the
 * device's own (`Device::toDocument()`), which is also what the provenance of a request nests.
 *
 * @extends JsonObjectType<Device>
 */
final class DeviceType extends JsonObjectType
{
    public const string NAME = 'beffroi_device';

    protected function encode(object $value): array
    {
        return $value->toDocument();
    }

    protected function decode(array $data): object
    {
        return Device::fromDocument($data);
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
