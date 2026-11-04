<?php

declare(strict_types=1);

use function Castor\guard_min_version;
use function Castor\import;

guard_min_version('v0.23.0');
// Tasks read getcwd(), so the working directory stays the one castor was started from.
defined('CASTOR_USE_CHDIR') || define('CASTOR_USE_CHDIR', false);

import(__DIR__ . '/.castor');
