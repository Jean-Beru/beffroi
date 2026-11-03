<?php

declare(strict_types=1);

namespace App\Message;

/**
 * A write the protocol needs the result of before answering (architecture §5.6). Every implementation
 * states its reason, and the contract of the provider routes the marker to "sync" (`MessengerContract`).
 */
interface SyncMessage
{
}
