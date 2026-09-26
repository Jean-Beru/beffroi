<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Exchange\PresentedTokenTypeInterface;
use Heidi\Oidc\Domain\Exchange\PresentedToken;
use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Heidi\Oidc\Exception\InvalidRequestException;
use SensitiveParameter;

/**
 * A type of token the exchange is wired to read, which reads what the test put in it: the values it answers
 * for, by the string they were presented as, and a refusal for anything else.
 */
final readonly class FakePresentedTokenType implements PresentedTokenTypeInterface
{
    /**
     * @param array<string, PresentedToken> $tokens by the value a request presents
     */
    public function __construct(
        private TokenTypeIdentifier $identifier,
        private array $tokens = [],
    ) {
    }

    public function identifier(): TokenTypeIdentifier
    {
        return $this->identifier;
    }

    public function read(Tenant $tenant, #[SensitiveParameter] string $token, DateTimeImmutable $now): PresentedToken
    {
        return $this->tokens[$token] ?? throw new InvalidRequestException('The presented token is not one this provider honours (RFC 8693 section 2.2.2).');
    }
}
