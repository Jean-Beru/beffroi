<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\Response;

use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Xml\Enc\PrivateDecryptionKey;

trait ResponseFixtures
{
    use AssertionFixtures;

    /**
     * M-3
     *
     * @param 'idp'|'sp'|'idp-b' $key
     */
    private static function identityProvider(
        string $entityId = 'https://idp.example.com/saml',
        string $key = 'idp',
    ): IdentityProvider {
        return new IdentityProvider(
            $entityId,
            [MetadataFixtures::certificate($key)],
            [],
            [new Endpoint(Binding::HttpRedirect, 'https://idp.example.com/saml/sso')],
        );
    }

    /**
     * @param 'idp'|'sp'|'sp-b' $key
     */
    private static function decryptionKey(string $key = 'sp'): PrivateDecryptionKey
    {
        return PrivateDecryptionKey::fromPem(MetadataFixtures::bytes(match ($key) {
            'idp' => 'keys/idp-signing-key.pem',
            'sp' => 'keys/sp-signing-key.pem',
            'sp-b' => 'keys/sp-b-encryption-key.pem',
        }));
    }

    private function unverified(string $fixture): UnverifiedResponse
    {
        return UnverifiedResponse::of($this->document($fixture));
    }
}
