<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;

/**
 * A PKCE method nothing of the module knows about, wired like any other: it names itself, it answers what
 * the test told it to, and it keeps what it was handed so that a caller which verifies a challenge itself
 * instead of asking is caught. "S512" is a transformation no specification defines, which is the point:
 * what the provider announces and takes is what the wiring holds. Never leaves the test suite.
 */
final class FakeCodeChallengeMethod implements CodeChallengeMethodInterface
{
    public ?string $challengeItWasHanded = null;

    public ?string $verifierItWasHanded = null;

    /**
     * @param non-empty-string $name
     */
    public function __construct(
        private readonly string $name = 'S512',
        private readonly bool $answer = true,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function verifies(string $challenge, string $codeVerifier): bool
    {
        $this->challengeItWasHanded = $challenge;
        $this->verifierItWasHanded = $codeVerifier;

        return $this->answer;
    }
}
