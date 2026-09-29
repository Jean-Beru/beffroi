<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Registration;

use DateInterval;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009: what a tenant does with a client that registers itself, and decision 0017, the one
 * thing such a policy may write on a registration it creates.
 */
final class ClientRegistrationPolicyTest extends TestCase
{
    /**
     * Decision 0009: closed is the absence of a policy, so a policy that names no mode is no policy.
     */
    #[Test]
    public function aPolicyNamesWhatAuthorisesARegistration(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A registration policy names what authorises a registration (decision 0009); a tenant that authorises none has no policy at all.');

        // When
        new ClientRegistrationPolicy('');
    }

    /**
     * Decision 0017: the exemption is written on the registration at the moment the policy creates it,
     * and it is the field decision 0008 already defined for a declared client.
     */
    #[Test]
    public function itWritesTheExemptionOnAConfidentialClient(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', true);

        // When
        $members = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([]));

        // Then
        static::assertSame(
            [
                'requires_pkce' => false,
            ],
            $members,
        );
    }

    /**
     * Decision 0017, RFC 9700 §2.1.1: a public client is never exempted, whatever the policy carries.
     */
    #[Test]
    public function itWritesNothingOnAPublicClient(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', true);

        // When
        $members = $policy->membersWrittenOn(Methods::none(), self::naming([]));

        // Then
        static::assertSame([], $members);
    }

    /**
     * Decision 0006: PKCE is the rule, and a policy that says nothing exempts nobody.
     */
    #[Test]
    public function aPolicyThatExemptsNobodyWritesNothing(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode');

        // When
        $members = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([]));

        // Then
        static::assertSame([], $members);
    }

    /**
     * RFC 7591 §2: a registration that names no scope is registered with the set the tenant wrote, which is
     * the one thing that makes such a client worth as much as a declared one of the same tenant.
     */
    #[Test]
    public function itWritesTheDefaultScopesOnARegistrationThatNamesNone(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', defaultScopes: Scopes::parse('openid offline_access'));

        // When
        $written = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([]));

        // Then
        static::assertSame(
            [
                'scope' => 'openid offline_access',
            ],
            $written,
        );
    }

    /**
     * A client that named its own scopes keeps them: what the policy writes is what the registration did
     * not say, and the row keeps what the policy wrote in front of what the client sent.
     */
    #[Test]
    public function itWritesNoScopeOnARegistrationThatNamesItsOwn(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', defaultScopes: Scopes::parse('openid offline_access'));

        // When
        $written = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([
            'scope' => 'openid',
        ]));

        // Then
        static::assertSame([], $written);
    }

    /**
     * A policy carries both of the things it may write, and writes both on the same registration: the
     * exemption of decision 0017 and the default set of scopes of RFC 7591 §2 answer two questions, and
     * neither is read in place of the other.
     */
    #[Test]
    public function itWritesEverythingItCarriesOnTheSameRegistration(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', true, defaultScopes: Scopes::parse('openid offline_access'));

        // When
        $written = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([]));

        // Then
        static::assertSame(
            [
                'scope' => 'openid offline_access',
                'requires_pkce' => false,
            ],
            $written,
        );
    }

    /**
     * A tenant that writes no default set of scopes writes none: its registrations take the "openid" the
     * registration itself takes when nobody says otherwise.
     */
    #[Test]
    public function aPolicyThatWritesNoDefaultScopesWritesNone(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode');

        // When
        $written = $policy->membersWrittenOn(Methods::clientSecretBasic(), self::naming([]));

        // Then
        static::assertSame([], $written);
    }

    /**
     * Decision 0009: what a tenant still keeps at one instant, as the two dates a store can ask its rows.
     */
    #[Test]
    public function aPolicyKeepsAClientUsedWithinTheDurationItNames(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', keepsAClientUnusedFor: new DateInterval('P30D'));

        // When
        $retention = $policy->retentionAt(Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('-30 days'), $retention->usedSince);
    }

    #[Test]
    public function aPolicyKeepsAClientNeverUsedForTheShorterDurationItNames(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode', keepsAClientNeverUsedFor: new DateInterval('PT1H'));

        // When
        $retention = $policy->retentionAt(Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('-1 hour'), $retention->registeredSince);
    }

    /**
     * The defaults of decision 0009: ninety days of no use for a client that was used, seven days of life
     * for one that never was.
     */
    #[Test]
    public function aPolicyThatNamesNoDurationTakesTheDefaultsOfTheDecision(): void
    {
        // Given
        $policy = new ClientRegistrationPolicy('a-mode');

        // When
        $retention = $policy->retentionAt(Fixtures::now());

        // Then
        static::assertEquals(Fixtures::now()->modify('-90 days'), $retention->usedSince);
        static::assertEquals(Fixtures::now()->modify('-7 days'), $retention->registeredSince);
    }

    /**
     * What a registration names of itself, which is what the policy leaves alone.
     *
     * @param array<string, mixed> $members
     */
    private static function naming(array $members): ClientMetadata
    {
        return new ClientMetadata([new RegisteredMembers($members)]);
    }
}
