<?php

declare(strict_types=1);

use Doctrine\Bundle\DoctrineBundle\DoctrineBundle;
use Heidi\Bundle\HeidiBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;

return [
    FrameworkBundle::class => [
        'all' => true,
    ],
    DoctrineBundle::class => [
        'all' => true,
    ],
    HeidiBundle::class => [
        'all' => true,
    ],
];
