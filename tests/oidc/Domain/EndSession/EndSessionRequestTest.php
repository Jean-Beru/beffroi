<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\EndSession;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\IdTokenHint;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\EndSession\EndSessionRequest;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class EndSessionRequestTest extends TestCase
{
    private Tenant $tenant;

    private Client $client;

    private IdTokenHint $hint;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->hint = new IdTokenHint(new Subject('alice-subject'), ['oidc-demo'], Uuid::v7());
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §3: the redirect exists when the client asked for one it registered,
     * with the state of the request.
     */
    #[Test]
    public function itRedirectsWhereTheClientAskedWithTheState(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, $this->client, $this->hint, $this->client->postLogoutRedirectUris[0], 'af0ifjsldkj');

        // When
        $redirect = $request->redirect() ?? static::fail('The request has a redirect.');

        // Then
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $redirect->toUri());
    }

    #[Test]
    public function itCarriesTheHintsOfTheUserInterface(): void
    {
        // When
        $request = new EndSessionRequest($this->tenant, $this->client, $this->hint, null, null, 'alice', ['fr-CA', 'fr']);

        // Then
        static::assertSame(['fr-CA', 'fr'], $request->uiLocales);
        static::assertSame('alice', $request->logoutHint);
    }

    /**
     * A logout link without parameters is a valid request (§2: every parameter is optional); it just
     * has nowhere to redirect to (§3).
     */
    #[Test]
    public function itMayNameNoClientAtAllAndThenRedirectsNowhere(): void
    {
        // When
        $request = new EndSessionRequest($this->tenant, null, null, null);

        // Then
        static::assertNull($request->client);
        static::assertNull($request->idTokenHint);
        static::assertNull($request->redirect());
        static::assertSame([], $request->uiLocales);
    }

    #[Test]
    public function itRedirectsNowhereWhenTheClientDidNotAsk(): void
    {
        // Given
        $request = new EndSessionRequest($this->tenant, $this->client, $this->hint, null, 'af0ifjsldkj');

        // When / Then
        static::assertNull($request->redirect());
    }

    /**
     * What the parser establishes, checked again: the client belongs to the tenant, the hint was issued
     * to it, the redirect URI is registered on it (§3), the state is not empty, a hint is verified or
     * invalid, not both.
     */
    #[Test]
    #[DataProvider('provideInconsistentRequests')]
    public function itRefusesAnInconsistentRequest(callable $build): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $build($this);
    }

    /**
     * @return iterable<string, array{callable(self): EndSessionRequest}>
     */
    public static function provideInconsistentRequests(): iterable
    {
        yield 'client of another tenant' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, Clients::public(Fixtures::tenant('other', 'https://id.other.example')), null, null),
        ];
        yield 'hint without a client' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, null, $test->hint, null),
        ];
        yield 'hint issued to another client' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, Clients::public($test->tenant), $test->hint, null),
        ];
        yield 'redirect without a client' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, null, null, new RedirectUri('https://demo.localhost/')),
        ];
        yield 'redirect not registered' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, $test->client, $test->hint, new RedirectUri('https://demo.localhost/other')),
        ];
        yield 'redirect registered for the authorization response only' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, $test->client, $test->hint, $test->client->redirectUris[0]),
        ];
        yield 'empty state' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, $test->client, $test->hint, null, ''),
        ];
        yield 'verified hint marked invalid' => [
            static fn (self $test): EndSessionRequest => new EndSessionRequest($test->tenant, $test->client, $test->hint, null, invalidIdTokenHint: true),
        ];
    }
}
