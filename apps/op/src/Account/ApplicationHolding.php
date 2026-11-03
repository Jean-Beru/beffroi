<?php

declare(strict_types=1);

namespace App\Account;

use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use DateTimeImmutable;
use function array_filter;
use function array_values;

/**
 * What one application holds of a person at this instant (issue #451): what they agreed to, what of it can
 * still be renewed, and what that application has asked that is waiting for an answer of theirs. The page
 * of that application and the console both read it, through ApplicationHoldings.
 *
 * A reading beside the objects it reads, and not a method of any of them: the question belongs to none of
 * them, and what answers it is three stores. "Renewable" is the only honest count of what is held: a
 * refresh token that was rotated, revoked or expired renews nothing, and a self-contained access token
 * already issued lives to its expiry whatever is done here (RFC 9068 §4), which both readers say in words
 * rather than counting it.
 */
final readonly class ApplicationHolding
{
    /**
     * @param list<BackchannelAuthenticationRecord> $pending oldest first
     */
    private function __construct(
        public Consent $consent,
        public int $renewable,
        public ?DateTimeImmutable $lastIssued,
        public array $pending,
    ) {
    }

    /**
     * @param list<RefreshToken> $refreshTokens whatever their state, as the store answers them
     * @param list<BackchannelAuthenticationRecord> $awaiting what waits for this person, every client of theirs
     */
    public static function of(Consent $consent, array $refreshTokens, array $awaiting, DateTimeImmutable $now): self
    {
        $renewable = 0;
        $lastIssued = null;
        foreach ($refreshTokens as $token) {
            // its own expiry is enough: the model refuses a refresh token that outlives its family, so a
            // family that expired is a token that expired with it (RefreshToken)
            if ($token->isRevoked() || $token->isRotated() || $token->expiresAt <= $now) {
                continue;
            }
            ++$renewable;
            if ($lastIssued === null || $token->issuedAt > $lastIssued) {
                $lastIssued = $token->issuedAt;
            }
        }

        return new self(
            $consent,
            $renewable,
            $lastIssued,
            array_values(array_filter(
                $awaiting,
                static fn (BackchannelAuthenticationRecord $record): bool => $record->clientId === $consent->clientId,
            )),
        );
    }
}
