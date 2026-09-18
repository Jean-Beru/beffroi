<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Heidi\Core\Domain\Session\Device;
use Heidi\Core\Domain\Session\DeviceType as DeviceKind;

/**
 * What a user agent parser said (architecture §3.5), as one JSON document on the session.
 *
 * @extends JsonObjectType<Device>
 */
final class DeviceType extends JsonObjectType
{
    public const string NAME = 'heidi_device';

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
