<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use Beffroi\Oidc\Application\Claims\OpenedPublicSubjectIdentifier;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedIdToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use function sprintf;

final class FakeIdTokenIssuer implements IdTokenIssuerInterface
{
    /**
     * @var list<array{UserAuthorizationInterface, AccessToken}>
     */
    public private(set) array $issued = [];

    public ?ClientKeysUnavailableException $unreadableKeys = null;

    public function address(Client $client): AddressedIdToken
    {
        if ($this->unreadableKeys !== null) {
            throw $this->unreadableKeys;
        }

        return new AddressedIdToken(
            new AddressedFormat(ResponseFormat::signed(), Keys::openedSigningKey($client->tenant)),
            new OpenedPublicSubjectIdentifier(),
        );
    }

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedIdToken $addressed, DateTimeImmutable $now): string
    {
        $this->issued[] = [$authorization, $accessToken];

        return sprintf(
            'id:%s:%s:%s:%d',
            $authorization->client->registration->clientId,
            $authorization->user->subject,
            $authorization->nonce ?? '-',
            $now->getTimestamp(),
        );
    }
}
