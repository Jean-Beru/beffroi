<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Fido\Conformance;

use function is_array;
use function is_bool;
use function is_string;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * The JSON body of a request of the FIDO2 server API, read member by member: a member of the wrong type
 * is a request refused, as a missing one the API requires.
 */
final readonly class ServerRequest
{
    /**
     * @param array<string, mixed> $members
     */
    private function __construct(
        private array $members,
    ) {
    }

    /**
     * @throws ServerRequestException when the body is not a JSON object
     */
    public static function fromRequest(Request $request): self
    {
        try {
            $members = $request->toArray();
        } catch (Throwable $exception) {
            throw new ServerRequestException('The body is not a JSON object.', previous: $exception);
        }
        $named = [];
        foreach ($members as $name => $value) {
            $named[(string) $name] = $value;
        }

        return new self($named);
    }

    /**
     * @throws ServerRequestException
     */
    public function string(string $name): string
    {
        $value = $this->optionalString($name);
        if ($value === null) {
            throw new ServerRequestException(sprintf('"%s" is required.', $name));
        }

        return $value;
    }

    /**
     * @throws ServerRequestException
     */
    public function optionalString(string $name): ?string
    {
        $value = $this->members[$name] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_string($value) || $value === '') {
            throw new ServerRequestException(sprintf('"%s" is not a non-empty string.', $name));
        }

        return $value;
    }

    /**
     * A member that is itself an object, or none.
     *
     * @throws ServerRequestException
     */
    public function optionalObject(string $name): ?self
    {
        $value = $this->members[$name] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_array($value)) {
            throw new ServerRequestException(sprintf('"%s" is not an object.', $name));
        }
        $named = [];
        foreach ($value as $member => $inner) {
            $named[(string) $member] = $inner;
        }

        return new self($named);
    }

    /**
     * @throws ServerRequestException
     */
    public function optionalBool(string $name): ?bool
    {
        $value = $this->members[$name] ?? null;
        if ($value !== null && ! is_bool($value)) {
            throw new ServerRequestException(sprintf('"%s" is not a boolean.', $name));
        }

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    public function members(): array
    {
        return $this->members;
    }
}
