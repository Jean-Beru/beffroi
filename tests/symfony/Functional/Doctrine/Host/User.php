<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\Host;

use Doctrine\ORM\Mapping as ORM;

/**
 * Decision 0002
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
