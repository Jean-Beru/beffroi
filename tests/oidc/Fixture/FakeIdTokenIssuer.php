<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use function sprintf;

/**
 * An issuer whose ID tokens say what they would carry, in clear. Never leaves the test suite: the real
 * one, JwtIdTokenIssuer, writes a signed JWT.
 */
final class FakeIdTokenIssuer implements IdTokenIssuerInterface
{
    /**
     * @var list<array{UserAuthorizationInterface, AccessToken}>
     */
    public private(set) array $issued = [];

    /**
     * What addressing an ID token throws while the keys of the client cannot be read, which a test sets and
     * takes back; null while they can.
     */
    public ?ClientKeysUnavailableException $unreadableKeys = null;

    public function address(Client $client): AddressedFormat
    {
        if ($this->unreadableKeys !== null) {
            throw $this->unreadableKeys;
        }

        return new AddressedFormat(ResponseFormat::signed(), Keys::openedSigningKey($client->tenant));
    }

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedFormat $addressed, DateTimeImmutable $now): string
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
