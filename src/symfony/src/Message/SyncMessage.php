<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * A write the protocol needs the result of before answering (architecture §5.6). Every implementation
 * states its reason and is listed with it in the messenger.yaml of the application.
 */
interface SyncMessage
{
}
