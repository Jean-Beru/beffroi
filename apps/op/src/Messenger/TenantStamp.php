<?php

declare(strict_types=1);

namespace App\Messenger;

use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\Messenger\Stamp\StampInterface;

/**
 * The scope a message was written under (decision 0020): the slug of the tenant, which the serializer puts
 * in a header of the transport so that a consumer knows which key to ask for before it touches the body,
 * and so that a message in the failure transport is read without being opened.
 *
 * **It says the scope and is never its authority.** What decides is the protected header of the sealed
 * body, which is the authenticated data of the JWE: a stamp swapped on a transport does not make a body
 * open under another scope, it makes the opening fail (the pattern of beffroi#436). Nothing of this
 * provider reads it to decide anything else.
 */
final readonly class TenantStamp implements StampInterface
{
    /**
     * @throws InvalidArgumentException when it names no tenant: a message is written under a scope or it
     *                                  is not written
     */
    public function __construct(
        public string $slug,
    ) {
        if ($slug === '') {
            throw new InvalidArgumentException('A message carries the slug of the tenant it is written for.');
        }
    }
}
