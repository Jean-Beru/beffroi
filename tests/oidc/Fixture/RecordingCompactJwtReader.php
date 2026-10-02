<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;

/**
 * The reader of the bridge, keeping what it was asked to read: a test that cares how many times a JWT is
 * read counts the strings here. Never leaves the test suite.
 */
final class RecordingCompactJwtReader implements CompactJwtReaderInterface
{
    /**
     * @var list<string>
     */
    public array $read = [];

    public function __construct(
        private readonly CompactJwtReaderInterface $reader = new JwtLibraryCompactJwtReader(),
    ) {
    }

    public function read(string $jwt): UnverifiedJwt
    {
        $this->read[] = $jwt;

        return $this->reader->read($jwt);
    }
}
