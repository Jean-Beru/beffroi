<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Authentication;

use Heidi\Core\Application\Authentication\SecondFactorRequirement;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2: a password alone does not sign in a user who holds an active second factor.
 */
final class SecondFactorRequirementTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private SecondFactorRequirement $requirement;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->credentials->save(
            new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$alice'), Fixtures::now()),
        );
        $this->requirement = new SecondFactorRequirement($this->credentials);
    }

    #[Test]
    public function aPasswordAloneSignsInAUserWithoutASecondFactor(): void
    {
        // When / Then
        static::assertFalse($this->requirement->requiredFor($this->alice));
    }

    #[Test]
    public function aPasskeyIsNotASecondFactor(): void
    {
        // Given
        $this->credentials->save(Fixtures::passkey($this->alice));

        // When / Then
        static::assertFalse($this->requirement->requiredFor($this->alice));
    }

    #[Test]
    public function anActiveTotpRequiresASecondFactor(): void
    {
        // Given
        $this->credentials->save(Totps::credential($this->alice, new FakePasswordHasher()));

        // When / Then
        static::assertTrue($this->requirement->requiredFor($this->alice));
    }

    #[Test]
    public function aRevokedTotpRequiresNothing(): void
    {
        // Given
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $totp->revoke(Fixtures::now()->modify('+1 hour'));
        $this->credentials->save($totp);

        // When / Then
        static::assertFalse($this->requirement->requiredFor($this->alice));
    }

    #[Test]
    public function theSecondFactorOfAnotherUserRequiresNothing(): void
    {
        // Given
        $bob = Fixtures::user(username: 'bob', subject: 'bob-subject');
        $this->credentials->save(Totps::credential($bob, new FakePasswordHasher()));

        // When / Then
        static::assertFalse($this->requirement->requiredFor($this->alice));
    }
}
