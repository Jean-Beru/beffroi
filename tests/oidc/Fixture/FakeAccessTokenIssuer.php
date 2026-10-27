<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Exception\KmsUnavailableException;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;
use function sprintf;

/**
 * An issuer whose tokens say who they were minted for, in clear, and live ten minutes. It names the
 * shape a test gives it, which is what makes an invented shape a fixture rather than a class of the
 * module. Never leaves the test suite: the real one, JwtAccessTokenIssuer, writes a signed at+jwt.
 */
final class FakeAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    /**
     * @var list<AuthorizationInterface>
     */
    public private(set) array $issued = [];

    /**
     * @var list<Client>
     */
    public private(set) array $addressed = [];

    /**
     * The authorizations whose tokens were addressed once they existed, in order.
     *
     * @var list<AuthorizationInterface>
     */
    public private(set) array $addressedFor = [];

    /**
     * What addressing a token throws while the KMS does not answer to open the key it is signed with, or to seal
     * what it carries sealed, which a test sets and takes back; null while it answers.
     */
    public ?KmsUnavailableException $kmsOutage = null;

    /**
     * @param non-empty-string $name the shape this issuer writes
     */
    public function __construct(
        private readonly string $name = 'jwt',
        private readonly DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function address(Client $client): AddressedAccessToken
    {
        if ($this->kmsOutage !== null) {
            throw $this->kmsOutage;
        }
        $this->addressed[] = $client;

        return new AddressedAccessToken();
    }

    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
    {
        if ($this->kmsOutage !== null) {
            throw $this->kmsOutage;
        }
        $this->addressedFor[] = $authorization;

        return new AddressedAccessToken();
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $this->issued[] = $authorization;

        return new AccessToken(
            sprintf(
                'at:%s:%s:%d',
                $authorization->client->registration->clientId,
                $authorization instanceof UserAuthorizationInterface ? $authorization->user->subject : $authorization->client->registration->clientId,
                $now->getTimestamp(),
            ),
            $now,
            $now->add($this->lifetime),
        );
    }
}
