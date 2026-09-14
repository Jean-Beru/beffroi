<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * Marks a message that must be handled in the current request, because the protocol needs its result before answering. Every implementation states why in its docblock.
 */
interface SyncMessage
{
}
