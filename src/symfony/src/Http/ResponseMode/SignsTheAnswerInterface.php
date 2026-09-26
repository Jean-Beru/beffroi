<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

/**
 * A way of answering whose answer is a document the tenant signs rather than a list of parameters
 * (JARM §2): what makes the response a fourth kind of JWS, with a lifetime the retirement of a key
 * accounts for (issue #155).
 *
 * A renderer declares this instead of anything reading its name: what the document announces beside the
 * modes, the algorithms it announces with them and the retirement window of the key that signs one are
 * decided from this, in one place (ServedResponseModesInterface).
 */
interface SignsTheAnswerInterface extends AuthorizationResponseRendererInterface
{
}
