<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Type;

use DateTimeImmutable;
use Doctrine\DBAL\Types\Exception\ValueNotConvertible;
use Exception;
use Heidi\Core\Domain\Session\RequestContext;
use function is_array;

/**
 * Where a request came from and with what (architecture §3.5), as one JSON document and one column.
 *
 * **One column and not five**, which is what lets the column seal. A sealed column is a Doctrine type
 * decorating a type, and the family a type seals under is the table it belongs to (decisions 0011 and
 * 0018); a context held as an embeddable fixes the type of each of its fields once for the whole model, so
 * the same field could not carry the type of each of the three tables that hold a context. Nothing is lost:
 * the object is `final readonly` and `withLocation()` and `withDevice()` return a new one, so no write ever
 * touched a single field, and nothing anywhere reads a column of a context on its own.
 *
 * `received_at` joins the document rather than keeping a column. It is a date and says nothing of a person,
 * so it could have stayed in the clear, but a column of its own would be a second column per context and
 * the dates every query of these three tables actually uses are their own (`established_at`, `issued_at`,
 * `expires_at`).
 *
 * It is written to the second, which is the precision the columns it replaces had (`TIMESTAMP(0)`), and
 * read back in the default timezone, which is what the Doctrine type of a datetime did.
 *
 * @extends JsonObjectType<RequestContext>
 */
final class RequestContextType extends JsonObjectType
{
    public const string NAME = 'heidi_request_context';

    /**
     * The format of a date in the document: to the second and with no offset, which is what a
     * `TIMESTAMP(0) WITHOUT TIME ZONE` held.
     */
    private const string RECEIVED_AT = 'Y-m-d H:i:s';

    private readonly GeoLocationType $locations;

    private readonly DeviceType $devices;

    public function __construct()
    {
        $this->locations = new GeoLocationType();
        $this->devices = new DeviceType();
    }

    protected function encode(object $value): array
    {
        return [
            'received_at' => $value->receivedAt->format(self::RECEIVED_AT),
            'ip_address' => $value->ipAddress,
            'user_agent' => $value->userAgent,
            'location' => $this->locations->document($value->location),
            'device' => $this->devices->document($value->device),
        ];
    }

    protected function decode(array $data): object
    {
        $receivedAt = $this->nullableString($data, 'received_at');
        if ($receivedAt === null) {
            throw ValueNotConvertible::new($data, self::NAME, 'A request context says when the request was received.');
        }

        try {
            $receivedAt = new DateTimeImmutable($receivedAt);
        } catch (Exception $exception) {
            throw ValueNotConvertible::new($data, self::NAME, $exception->getMessage(), $exception);
        }

        return new RequestContext(
            $receivedAt,
            $this->nullableString($data, 'ip_address'),
            $this->nullableString($data, 'user_agent'),
            $this->locations->of($this->nested($data, 'location')),
            $this->devices->of($this->nested($data, 'device')),
        );
    }

    protected function expects(): string
    {
        return RequestContext::class;
    }

    protected function name(): string
    {
        return self::NAME;
    }

    /**
     * @param array<array-key, mixed> $data
     *
     * @return array<array-key, mixed>|null
     */
    private function nested(array $data, string $key): ?array
    {
        $value = $data[$key] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_array($value)) {
            throw ValueNotConvertible::new($data, self::NAME, 'The member "' . $key . '" must be an object or absent.');
        }

        return $value;
    }
}
