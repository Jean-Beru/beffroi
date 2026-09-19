<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;

/**
 * What LoginFailureListener tells the core of a refused login: the shape of AuthenticationFailed without
 * its moment, its tenant and its context.
 */
final readonly class LoginFailure
{
    public function __construct(
        public ?AuthenticationMethod $method,
        public AuthenticationFailureReason $reason,
        public ?string $identifier,
        public ?User $user,
    ) {
    }
}
