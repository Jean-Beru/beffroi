<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleLogout\SignOutResponse;
use Beffroi\Saml\Port\SignOutResponderInterface;

/**
 * A responder that keeps what it was asked to write, and answers with a URL naming where it goes.
 */
final class RecordingSignOutResponder implements SignOutResponderInterface
{
    public private(set) ?SignOutResponse $response = null;

    public function answer(Tenant $tenant, SignOutResponse $response): RedirectedMessage
    {
        $this->response = $response;

        return new RedirectedMessage($response->request->answerLocation . '?SAMLResponse=answered');
    }
}
