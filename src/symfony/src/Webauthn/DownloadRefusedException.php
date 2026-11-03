<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Webauthn;

use RuntimeException;

/**
 * What the console went to download for the passkeys of the deployment did not come back as a document: the
 * service redirected, answered anything but 200, or could not be reached (DocumentDownload). Nothing is kept.
 */
final class DownloadRefusedException extends RuntimeException
{
}
