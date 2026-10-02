<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;

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
