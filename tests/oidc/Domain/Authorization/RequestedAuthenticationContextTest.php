<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\UnmetAuthenticationRequirementsException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Logins;
use Beffroi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.5.1.1, Decision 0010
 */
final class RequestedAuthenticationContextTest extends TestCase
{
    private Client $client;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::public($tenant);
        $this->session = Fixtures::session(Fixtures::user($tenant));
    }

    #[Test]
    public function aRequestThatNamesNoClassPutsNoneInQuestion(): void
    {
        // When / Then
        static::assertFalse($this->context()->isInQuestion());
    }

    #[Test]
    public function aRequestThatNamesAClassTheProviderCanProvePutsItInQuestion(): void
    {
        // When / Then
        static::assertTrue($this->context(acrValues: ['phr'])->isInQuestion());
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aClassNoWiredLoginCanProvePutsNothingInQuestion(): void
    {
        // When / Then
        static::assertFalse($this->context(acrValues: ['phr'], logins: Logins::passwordOnly())->isInQuestion());
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialClassTheProviderCannotProveIsRefusedBeforeAnyLogin(): void
    {
        // Given
        $context = $this->context(claims: '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}', logins: Logins::passwordOnly());

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);
        $this->expectExceptionMessageIsOrContains('acr_values_supported');

        // When
        $context->assertTheProviderCanProveOne();
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function aVoluntaryClassTheProviderCannotProveIsNotRefused(): void
    {
        // Given
        $context = $this->context(acrValues: ['phr'], logins: Logins::passwordOnly());

        // When
        $context->assertTheProviderCanProveOne();

        // Then
        static::assertFalse($context->isInQuestion(), 'nothing is in question, and nothing is refused either');
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialClassNoCredentialOfTheUserCouldMeetIsRefused(): void
    {
        // Given
        $context = $this->context(claims: '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}');

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);
        $this->expectExceptionMessageIsOrContains('holds no credential able to satisfy');

        // When
        $context->assertTheUserCouldMeetIt($this->session, null);
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aClassACredentialOfTheUserWouldSatisfyIsAStepUp(): void
    {
        // Given
        $context = $this->context(claims: '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}');
        $passkey = Fixtures::passkey($this->session->user);

        // When
        $stepUp = $context->stepUpFor($this->session, [$passkey]);

        // Then
        static::assertNotNull($stepUp);
        $context->assertTheUserCouldMeetIt($this->session, $stepUp);
    }

    #[Test]
    public function aStepUpOffersNoKindTheFloorOfTheTenantForbids(): void
    {
        // Given
        $hardened = Fixtures::hardenedTenant();
        $user = Fixtures::user($hardened);
        $session = Fixtures::session($user, null, AuthenticationProofs::of(new AuthenticationMethod('swk'), Fixtures::now()));
        $context = $this->contextOf($hardened);

        // When / Then
        static::assertNull($context->stepUpFor($session, [Fixtures::password($user)]));
    }

    #[Test]
    public function aTenantThatNamedNoFloorOffersThePasswordForThatStepUp(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $session = Fixtures::session($user, null, AuthenticationProofs::of(new AuthenticationMethod('swk'), Fixtures::now()));
        $context = $this->contextOf($tenant);

        // When
        $stepUp = $context->stepUpFor($session, [Fixtures::password($user)]);

        // Then
        static::assertSame(['password'], $stepUp?->kinds());
    }

    /**
     * Decision 0010
     */
    #[Test]
    public function aSessionThatAlreadySatisfiesAClassStepsUpToNothing(): void
    {
        // Given
        $context = $this->context(acrValues: [$this->session->authenticationContextClass()->value]);

        // When / Then
        static::assertNull($context->stepUpFor($this->session, [Fixtures::passkey($this->session->user)]));
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function anEssentialClassTheSessionDoesNotSatisfyIsRefusedAfterTheLogin(): void
    {
        // Given
        $context = $this->context(claims: '{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}');

        // Then
        $this->expectException(UnmetAuthenticationRequirementsException::class);
        $this->expectExceptionMessageIsOrContains('did not authenticate as any requested acr value demands');

        // When
        $context->assertMetBy($this->session);
    }

    /**
     * OIDC Core §2
     */
    #[Test]
    public function theClassOfTheGrantIsTheOneTheSessionHasWhenNoneWasAsked(): void
    {
        // When / Then
        static::assertSame($this->session->authenticationContextClass()->value, $this->context()->classFor($this->session)->value);
    }

    private function contextOf(Tenant $tenant): RequestedAuthenticationContext
    {
        return RequestedAuthenticationContext::of(
            Requests::authorization(
                Clients::public($tenant),
                claims: ClaimsRequest::fromJson('{"id_token": {"acr": {"essential": true, "values": ["2"]}}}'),
            ),
            Logins::passwordAndPasskey()->provableMethods($tenant),
        );
    }

    /**
     * @param list<string> $acrValues
     */
    private function context(array $acrValues = [], ?string $claims = null, ?Logins $logins = null): RequestedAuthenticationContext
    {
        $request = Requests::authorization(
            $this->client,
            acrValues: $acrValues,
            claims: $claims === null ? null : ClaimsRequest::fromJson($claims),
        );

        return RequestedAuthenticationContext::of($request, ($logins ?? Logins::passwordAndPasskey())->provableMethods($this->client->tenant));
    }
}
