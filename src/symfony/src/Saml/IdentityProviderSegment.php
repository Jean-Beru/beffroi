<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelEntityId;

/**
 * The last segment of the URL of the metadata given to one upstream identity provider (beffroi/saml, spec/saml.md
 * S-65): its entity ID in the base64url of RFC 4648 §5 without padding. An entity ID is a URI, whose "/", "?", "#" and
 * "%" a path segment would carry percent-encoded and a server or a proxy on the way merges or decodes; base64url is one
 * segment of letters, digits, "-" and "_", read back without a table of the providers, so that an operator writes the
 * URL from the entity ID alone and the route reads the entity ID from the URL alone.
 */
final class IdentityProviderSegment
{
    /**
     * What the route requires of the segment: base64url, which the router refuses otherwise before anything is read.
     */
    public const string REQUIREMENT = '[A-Za-z0-9_-]+';

    private function __construct()
    {
    }

    public static function of(string $entityId): string
    {
        return Base64Url::encode($entityId);
    }

    /**
     * The entity ID the segment names, null when it is not base64url or its value is no entity ID (M-6).
     */
    public static function entityIdOf(string $segment): ?string
    {
        $entityId = Base64Url::decode($segment);
        if ($entityId === null) {
            return null;
        }

        try {
            return ModelEntityId::read($entityId);
        } catch (InvalidArgumentException) {
            return null;
        }
    }
}
