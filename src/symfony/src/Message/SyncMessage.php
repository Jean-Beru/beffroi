<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

/**
 * A write that must be handled in the current request, because the protocol needs its result before
 * answering (architecture §5.6): the interaction persisted before the redirect to the login, the session
 * created at login, the consent recorded before the code is issued, the code issued before the redirect to
 * the relying party, the code consumed and the refresh token issued or rotated in the token request, the
 * session ended and its refresh tokens revoked at logout. The list is closed. Every implementation states
 * its reason in its docblock and is listed, with that reason, in the messenger.yaml of the application;
 * it does not implement Command.
 */
interface SyncMessage
{
}
