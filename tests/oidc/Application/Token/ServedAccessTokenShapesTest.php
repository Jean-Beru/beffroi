<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\ServedAccessTokenShapes;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ServedAccessTokenShapesTest extends TestCase
{
    private AuthenticationSession $session;

    private FakeAccessTokenIssuer $jwt;

    private FakeAccessTokenIssuer $opaque;

    private ServedAccessTokenShapes $shapes;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->jwt = new FakeAccessTokenIssuer('jwt');
        $this->opaque = new FakeAccessTokenIssuer('opaque');
        $this->shapes = new ServedAccessTokenShapes([$this->jwt, $this->opaque]);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function aClientRegisteredForJwtGetsItsTokenFromTheJwtIssuer(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::jwt());

        // When
        $token = Tokens::accessToken($this->shapes, $authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->jwt->issued);
        static::assertSame([], $this->opaque->issued);
        static::assertStringStartsWith('at:oidc-demo:', $token->value);
    }

    #[Test]
    public function aClientRegisteredForOpaqueTokensGetsItsTokenFromTheOpaqueIssuer(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::opaque());

        // When
        $token = Tokens::accessToken($this->shapes, $authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->opaque->issued);
        static::assertSame([], $this->jwt->issued);
        static::assertStringStartsWith('at:oidc-demo:', $token->value);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function theTokenOfAClientIsAddressedByTheIssuerOfItsShape(): void
    {
        // Given
        $client = $this->authorization(Shapes::opaque())->client;

        // When
        $this->shapes->address($client);

        // Then
        static::assertSame([$client], $this->opaque->addressed);
        static::assertSame([], $this->jwt->addressed);
    }

    #[Test]
    public function theTokenOfAnAuthorizationIsAddressedByTheIssuerOfItsShape(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::opaque());

        // When
        $this->shapes->addressFor($authorization);

        // Then
        static::assertSame([$authorization], $this->opaque->addressedFor);
        static::assertSame([], $this->jwt->addressedFor);
    }

    #[Test]
    public function anInventedShapeIsMintedByTheIssuerThatNamesIt(): void
    {
        // Given
        $invented = new FakeAccessTokenIssuer('invented');
        $shapes = new ServedAccessTokenShapes([$this->jwt, $this->opaque, $invented]);
        $authorization = $this->authorization(Shapes::invented());

        // When
        Tokens::accessToken($shapes, $authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $invented->issued);
        static::assertSame([], $this->jwt->issued);
    }

    #[Test]
    public function theWiredShapesAreNamedInTheOrderTheyAreWired(): void
    {
        // When
        $shapes = $this->shapes->servedAccessTokenShapes();

        // Then
        static::assertSame(['jwt', 'opaque'], array_map(
            static fn (AccessTokenShapeInterface $shape): string => $shape->name(),
            $shapes,
        ));
    }

    #[Test]
    public function aProviderThatWritesOneShapeServesIt(): void
    {
        // Given
        $shapes = new ServedAccessTokenShapes([$this->opaque]);

        // When
        $served = $shapes->servedAccessTokenShapes();

        // Then
        static::assertSame([$this->opaque], $served);
    }

    #[Test]
    public function twoIssuersOfOneShapeAreRefused(): void
    {
        // Given
        $shapes = new ServedAccessTokenShapes([$this->jwt, new FakeAccessTokenIssuer('jwt')]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two issuers write access tokens in the "jwt" shape.');

        // When
        $shapes->servedAccessTokenShapes();
    }

    #[Test]
    public function aProviderThatWritesNoShapeAtAllIsRefused(): void
    {
        // Given
        $shapes = new ServedAccessTokenShapes([]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider writes its access tokens in at least one shape.');

        // When
        $shapes->servedAccessTokenShapes();
    }

    #[Test]
    public function aShapeNoIssuerWritesIsRefusedWithTheWiredOnes(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::invented());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No issuer writes access tokens in the "invented" shape; the wired shapes are jwt, opaque.');

        // When
        Tokens::accessToken($this->shapes, $authorization, Fixtures::now());
    }

    private function authorization(AccessTokenShapeInterface $shape): UserAuthorization
    {
        $client = Clients::confidential($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET), accessTokenShape: $shape);

        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code('the-code', $client, $this->session, Fixtures::now()));
    }
}
