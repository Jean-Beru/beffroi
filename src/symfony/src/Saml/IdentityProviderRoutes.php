<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

/**
 * The routes of the SAML identity provider of a tenant, their names and their paths under the prefix the bundle is
 * mounted at, which is the path of the issuer (spec/saml.md section 5.1). The metadata names the three, and two are
 * served today, the metadata and the single sign-on service (issue #731), beside the route where the login sends back
 * a request that waited for it; the single logout service is issues #734 and #735's. The controllers take their route
 * from here, so that what the metadata announced is where they answer.
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

    /**
     * Where the login of the provider sends back a browser whose SAML request waited for it (spec/saml.md S-18).
     */
    public const string SINGLE_SIGN_ON_RESUME = 'beffroi_interaction_saml_single_sign_on_resume';

    public const string SINGLE_SIGN_ON_RESUME_PATH = '/saml/sso/resume';

    /**
     * The parameter of the resume route that names the request waiting, a reference this provider wrote.
     */
    public const string REFERENCE_PARAMETER = 'request';

    public const string SINGLE_LOGOUT = 'beffroi_interaction_saml_single_logout';

    public const string SINGLE_LOGOUT_PATH = '/saml/slo';

    private function __construct()
    {
    }
}
