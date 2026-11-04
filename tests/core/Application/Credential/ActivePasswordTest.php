<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.1
 */
final class ActivePasswordTest extends TestCase
{
    private InMemoryCredentialRepository $credentials;

    private ActivePassword $activePassword;

    protected function setUp(): void
    {
        $this->credentials = new InMemoryCredentialRepository();
        $this->activePassword = new ActivePassword(new ActiveCredentials($this->credentials));
    }

    #[Test]
    public function thePasswordOfAPersonIsTheOneTheyHold(): void
    {
        // Given
        $alice = Fixtures::user();
        $password = Fixtures::password($alice);
        $this->credentials->save($password);

        // When / Then
        static::assertSame($password, $this->activePassword->of($alice));
    }

    #[Test]
    public function aPersonWhoSignsInByAnotherMeansHoldsNone(): void
    {
        // Given
        $alice = Fixtures::user();
        $this->credentials->save(Fixtures::passkey($alice));

        // When / Then
        static::assertNull($this->activePassword->of($alice));
    }

    #[Test]
    public function thePasswordOfSomebodyElseIsNotTheirs(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $alice = Fixtures::user($tenant);
        $bob = Fixtures::user($tenant, 'bob', 'bob-subject');
        $this->credentials->save(Fixtures::password($bob));

        // When / Then
        static::assertNull($this->activePassword->of($alice));
    }
}
