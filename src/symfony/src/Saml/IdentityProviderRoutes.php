<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

/**
 * The routes of the SAML identity provider of a tenant, their names and their paths under the prefix the bundle is
 * mounted at, which is the path of the issuer (spec/saml.md section 5.1). The metadata names the three, and one only
 * is served today: the single sign-on service is issue #731's and the single logout service issues #734 and #735's,
 * whose controllers take their route from here, so that what the metadata announced is where they answer.
 *
 * The metadata is read server to server, the protocol plane; both services are reached by the browser, the plane of
 * the interactions (architecture §5.2).
 */
final class IdentityProviderRoutes
{
    public const string METADATA = 'beffroi_protocol_saml_metadata';

    public const string METADATA_PATH = '/saml/metadata';

    public const string SINGLE_SIGN_ON = 'beffroi_interaction_saml_single_sign_on';

    public const string SINGLE_SIGN_ON_PATH = '/saml/sso';

    public const string SINGLE_LOGOUT = 'beffroi_interaction_saml_single_logout';

    public const string SINGLE_LOGOUT_PATH = '/saml/slo';

    private function __construct()
    {
    }
}
