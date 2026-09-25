<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\ServedAccessTokenShapes;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Shapes;
use Heidi\Oidc\Tests\Fixture\Tokens;
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
     * Architecture §4.6: the registration of the client picks the issuer, and that one alone mints.
     */
    #[Test]
    public function aClientRegisteredForJwtGetsItsTokenFromTheJwtIssuer(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::jwt());

        // When
        $token = $this->shapes->issue($authorization, Fixtures::now());

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
        $token = $this->shapes->issue($authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->opaque->issued);
        static::assertSame([], $this->jwt->issued);
        static::assertStringStartsWith('at:oidc-demo:', $token->value);
    }

    /**
     * Issue #239: a shape is added by a class and a line in the wiring, and the token endpoint mints in
     * it without anything here knowing its name.
     */
    #[Test]
    public function anInventedShapeIsMintedByTheIssuerThatNamesIt(): void
    {
        // Given
        $invented = new FakeAccessTokenIssuer('invented');
        $shapes = new ServedAccessTokenShapes([$this->jwt, $this->opaque, $invented]);
        $authorization = $this->authorization(Shapes::invented());

        // When
        $shapes->issue($authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $invented->issued);
        static::assertSame([], $this->jwt->issued);
    }

    /**
     * What a client may register is the wired list, in the order it is wired, and the first of them is
     * what a client that registers none takes.
     */
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

    /**
     * A deployment that writes one shape only boots, which is what an enumeration demanding an issuer
     * for every case made impossible (issue #239).
     */
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

    /**
     * A registration built against another wiring, which nothing here writes: the refusal names what is
     * wired rather than what was asked for.
     */
    #[Test]
    public function aShapeNoIssuerWritesIsRefusedWithTheWiredOnes(): void
    {
        // Given
        $authorization = $this->authorization(Shapes::invented());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No issuer writes access tokens in the "invented" shape; the wired shapes are jwt, opaque.');

        // When
        $this->shapes->issue($authorization, Fixtures::now());
    }

    private function authorization(AccessTokenShapeInterface $shape): UserAuthorization
    {
        $client = Clients::confidential($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET), accessTokenShape: $shape);

        return UserAuthorization::fromAuthorizationCode(Grants::authorizationCode(), Tokens::code('the-code', $client, $this->session, Fixtures::now()));
    }
}
