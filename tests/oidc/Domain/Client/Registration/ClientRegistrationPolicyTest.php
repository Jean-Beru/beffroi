<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Registration;

use DateInterval;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009, Decision 0017
 */
final class ClientRegistrationPolicyTest extends TestCase
{
    /**
     * Decision 0009
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
     * Decision 0017
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
     * Decision 0017, RFC 9700 §2.1.1
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
     * Decision 0006
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
     * RFC 7591 §2
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
     * Decision 0017, RFC 7591 §2
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
     * Decision 0009
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
     * Decision 0009
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
     * @param array<string, mixed> $members
     */
    private static function naming(array $members): ClientMetadata
    {
        return new ClientMetadata([new RegisteredMembers($members)]);
    }
}
