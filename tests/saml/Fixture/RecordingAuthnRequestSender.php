<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Beffroi\Saml\Port\AuthnRequestSenderInterface;

final class RecordingAuthnRequestSender implements AuthnRequestSenderInterface
{
    public const string ID = '_8f3a1c2e9b7d4a6f0c5e1b3d2a4f6c8e0b1d3f5a';

    public const string LOCATION = 'https://idp.example.org/saml/sso';

    public const string REFUSED = 'https://idp.refused.example/saml';

    /**
     * @var list<UpstreamAuthnRequest>
     */
    public private(set) array $sent = [];

    public function send(Tenant $tenant, UpstreamAuthnRequest $request): SentAuthnRequest
    {
        $this->sent[] = $request;

        return new SentAuthnRequest($request, self::ID, new RedirectedMessage(self::LOCATION . '?SAMLRequest=written'));
    }

    public function destination(Tenant $tenant, string $identityProvider): string
    {
        if ($identityProvider === self::REFUSED) {
            throw new UpstreamSignOnRefusedException('The identity provider has no metadata accepted yet (spec/saml.md S-48).');
        }

        return self::LOCATION;
    }
}
