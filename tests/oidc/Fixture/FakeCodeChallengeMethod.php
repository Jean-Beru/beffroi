<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;

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
