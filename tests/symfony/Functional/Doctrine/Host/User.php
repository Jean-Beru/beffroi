<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine\Host;

use Doctrine\ORM\Mapping as ORM;

/**
 * The "User" of the host application: the bundle never hooks onto it (decision 0002), its table sits next
 * to heidi_user and neither knows the other.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_user')]
final class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    public private(set) ?int $id = null;

    public function __construct(
        #[ORM\Column(type: 'string', length: 255)]
        public readonly string $email,
    ) {
    }
}
