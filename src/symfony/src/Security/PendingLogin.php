<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * A login the firewall verified a first factor of and holds until the second one (architecture §5.4):
 * who proved what, and until when a code completes it; past that, the password is typed again. It opens
 * no session and grants nothing: what the browser holds between the two steps is this, and no token of
 * the firewall.
 */
final readonly class PendingLogin
{
    /**
     * Five minutes to type a code, ten times what a step of the authenticator lasts.
     */
    public const string LIFETIME = 'PT5M';

    /**
     * @param non-empty-list<AuthenticationMethod> $methods what the first step proved
     */
    public function __construct(
        public Uuid $userId,
        public array $methods,
        public DateTimeImmutable $provenAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($methods === []) {
            throw new InvalidArgumentException('A pending login holds what its first step proved.');
        }
        if ($expiresAt <= $provenAt) {
            throw new InvalidArgumentException('A pending login expires after its first step.');
        }
    }

    /**
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public static function provenAt(Uuid $userId, array $methods, DateTimeImmutable $now): self
    {
        return new self($userId, $methods, $now, $now->add(new DateInterval(self::LIFETIME)));
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
