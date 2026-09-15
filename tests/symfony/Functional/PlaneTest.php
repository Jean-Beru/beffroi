<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional;

use Heidi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

/**
 * Architecture §5.2 and §6: HEIDI_PLANE restricts a process to one plane; the routes of the other plane get
 * the 404 an unknown path gets, the routes of the host application are never touched. The plane is read
 * from the environment when the process starts, on the same compiled container.
 *
 * A route that is served answers what its controller answers: 200 for the JWK Set, 400 for a login page
 * reached without an interaction; a route that is refused answers 404, the same as an unknown path.
 */
final class PlaneTest extends DatabaseTestCase
{
    private const int LOGIN_SERVED = 400;

    private const int JWKS_SERVED = 200;

    protected function setUp(): void
    {
        // the browser is created by the test, after the plane is set
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['HEIDI_PLANE'], $_ENV['HEIDI_PLANE']);
    }

    /**
     * @return iterable<string, array{string|null, string, int}>
     */
    public static function requests(): iterable
    {
        yield 'a protocol process refuses the login' => ['protocol', '/login', 404];
        yield 'a protocol process serves the JWK Set' => ['protocol', '/jwks', self::JWKS_SERVED];
        yield 'a protocol process leaves the host application alone' => ['protocol', '/host', 200];
        yield 'an interaction process serves the login' => ['interaction', '/login', self::LOGIN_SERVED];
        yield 'an interaction process refuses the JWK Set' => ['interaction', '/jwks', 404];
        yield 'an interaction process leaves the host application alone' => ['interaction', '/host', 200];
        yield 'a process serving all planes serves the login' => ['all', '/login', self::LOGIN_SERVED];
        yield 'a process serving all planes serves the JWK Set' => ['all', '/jwks', self::JWKS_SERVED];
        yield 'without HEIDI_PLANE a process serves the login' => [null, '/login', self::LOGIN_SERVED];
        yield 'without HEIDI_PLANE a process serves the JWK Set' => [null, '/jwks', self::JWKS_SERVED];
        yield 'an unknown path is a 404 on every plane' => ['protocol', '/unknown', 404];
    }

    #[Test]
    #[DataProvider('requests')]
    public function aProcessAnswersTheRoutesOfItsPlaneOnly(?string $plane, string $path, int $status): void
    {
        if ($plane !== null) {
            $_SERVER['HEIDI_PLANE'] = $plane;
        }
        $browser = self::browser();

        $browser->request('GET', $path);

        static::assertSame($status, $browser->getResponse()->getStatusCode());
    }

    /**
     * A plane that does not exist is not "all": the process refuses to serve at all.
     */
    #[Test]
    public function anUnknownPlaneIsRefused(): void
    {
        $_SERVER['HEIDI_PLANE'] = 'everything';
        $browser = self::browser();
        $browser->catchExceptions(false);

        $this->expectException(RuntimeException::class);
        $browser->request('GET', '/host');
    }
}
