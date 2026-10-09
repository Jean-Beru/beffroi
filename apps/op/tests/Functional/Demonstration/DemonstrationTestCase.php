<?php

declare(strict_types=1);

namespace App\Tests\Functional\Demonstration;

use App\Demonstration\Trace\TraceStore;
use App\Tests\Functional\BrowserTestCase;
use Psr\Cache\CacheItemPoolInterface;

/**
 * A browser on the pages of the demonstration (issue #462). What it adds to the browser of the
 * application is one thing: the trace lives in a cache pool, which outlives a test where a table does
 * not, so it is emptied before every one of them and a test reads what itself did and nothing else.
 */
abstract class DemonstrationTestCase extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::service('test.app.demonstration_trace_pool', CacheItemPoolInterface::class)->clear();
    }

    protected static function traces(): TraceStore
    {
        return self::service('test.app.demonstration_traces', TraceStore::class);
    }
}
