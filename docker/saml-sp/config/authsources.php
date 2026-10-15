<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, and the one the judge plays: the service provider
// "beffroi", given its entity ID, the provider of the stack, its own signing pair (the certificate of its metadata, for
// the signature of its requests and the key a later story encrypts an assertion for) and signed requests in both
// bindings. The identity provider is the entity of the metadata the stack serves; where its metadata come from, and how
// they are read, is metadata/saml20-idp-remote.php.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['beffroi'] = [
    'saml:SP',
    'entityID' => 'https://saml-sp.localhost/simplesaml/module.php/saml/sp/metadata/beffroi',
    'idp' => 'https://op.localhost/saml/metadata',
    'privatekey' => 'sp.pem',
    'certificate' => 'sp.crt',
    'sign.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,
];
