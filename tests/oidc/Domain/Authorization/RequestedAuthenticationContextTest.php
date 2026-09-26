<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\UnmetAuthenticationRequirementsException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Logins;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The rules of a requested "acr" (OIDC Core §5.5.1.1, decision 0010), asked of the request and of the session
 * and of nothing else: issue #251 moved them out of the handler so that they could be read and tested without
 * a store to ask, a clock to move or a page to reach. Nothing here names a repository.
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

    /**
     * A request that names no class asks for none in particular, so the credentials of the user are worth
     * nothing to it and are not read.
     */
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
     * Decision 0010: a class no wired login can prove is one the provider cannot assert, so nothing is in
     * question and no credential is read for it.
     */
    #[Test]
    public function aClassNoWiredLoginCanProvePutsNothingInQuestion(): void
    {
        // When / Then
        static::assertFalse($this->context(acrValues: ['phr'], logins: Logins::passwordOnly())->isInQuestion());
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" naming only classes the provider cannot assert fails before any
     * login, the user being able to do nothing about it on a page.
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
     * OIDC Core §5.5.1.1: a voluntary request is never refused, whatever the provider can prove.
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
     * OIDC Core §5.5.1.1: an essential "acr" the session does not satisfy and no credential of the user could
     * is a failed authentication before any page.
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
     * Decision 0010: a credential of the user would satisfy it, so the login page asks for what is missing
     * rather than refusing.
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

    /**
     * Decision 0010: a session that already satisfies a requested class has nothing to step up to.
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
     * OIDC Core §5.5.1.1: an essential "acr" still unsatisfied once the login is done is a failed
     * authentication.
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
     * OIDC Core §2: the class every token of the grant will name is the requested one the session satisfies,
     * and the one the session has when the request asked for none in particular.
     */
    #[Test]
    public function theClassOfTheGrantIsTheOneTheSessionHasWhenNoneWasAsked(): void
    {
        // When / Then
        static::assertSame($this->session->authenticationContextClass()->value, $this->context()->classFor($this->session)->value);
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

        return RequestedAuthenticationContext::of($request, ($logins ?? Logins::passwordAndPasskey())->provableMethods());
    }
}
