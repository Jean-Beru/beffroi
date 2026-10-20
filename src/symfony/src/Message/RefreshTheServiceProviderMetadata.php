<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * The metadata of every service provider of the tenant read again (beffroi/saml, spec/saml.md section 6.2): recurring
 * and idempotent, a document read again as it was accepted writing nothing, and a refusal keeping the document
 * accepted until the next tick.
 */
final readonly class RefreshTheServiceProviderMetadata implements Command
{
}
