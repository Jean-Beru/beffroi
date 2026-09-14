<?php

declare(strict_types=1);

use Heidi\Bundle\HeidiBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;

return [
    FrameworkBundle::class => [
        'all' => true,
    ],
    HeidiBundle::class => [
        'all' => true,
    ],
];
