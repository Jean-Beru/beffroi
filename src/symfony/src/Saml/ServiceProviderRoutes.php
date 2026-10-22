<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

/**
 * The routes of the SAML service provider of a tenant, their names and their paths under the prefix the bundle is
 * mounted at, which is the path of the issuer (spec/saml.md section 5.6). The metadata names both and one is served
 * today: the assertion consumer service is issue #784's, whose controller takes its route from here, so that what the
 * metadata announced is where it answers (S-39).
 *
 * The metadata is read server to server, the protocol plane; the assertion consumer service is where the browser posts
 * a response, the plane of the interactions (architecture §5.2).
 */
final class ServiceProviderRoutes
{
    public const string METADATA = 'beffroi_protocol_saml_service_provider_metadata';

    public const string METADATA_PATH = '/saml/sp/metadata';

    public const string ASSERTION_CONSUMER_SERVICE = 'beffroi_interaction_saml_assertion_consumer_service';

    public const string ASSERTION_CONSUMER_SERVICE_PATH = '/saml/sp/acs';

    private function __construct()
    {
    }
}
