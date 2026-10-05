<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([
    SetList::DEAD_CODE,
    LevelSetList::UP_TO_PHP_84,
    PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    PHPUnitSetList::ANNOTATIONS_TO_ATTRIBUTES,
]);
$builder->withComposerBased(phpunit: true, symfony: true);
$builder->withPhpVersion(PhpVersion::PHP_84);
$builder->withPaths([
    __DIR__ . '/../src',
    __DIR__ . '/../tests',
    __DIR__ . '/../castor.php',
    __DIR__ . '/../.castor',
    __DIR__ . '/rector.php',
]);
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
]);
$builder->withParallel();
// A hash per file, so a run re-reads only what changed. The directory is of the repository and not of
// the system temporary one, which is where the CI keeps it from one run to the next (ci.yml) and which
// a container of the QA image does not carry over. Rector drops the whole cache itself when the
// snapshot of this configuration changes, so nothing here has to be invalidated by hand.
$builder->withCache(__DIR__ . '/cache/rector');
$builder->withImportNames();

return $builder;
