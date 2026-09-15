<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

/**
 * Architecture §5.2 and §6: HEIDI_PLANE restricts a process to one plane; the routes of the other plane get
 * the 404 an unknown path gets, the routes of the host application are never touched. The plane is read
 * from the environment when the process starts, on the same compiled container.
 */
final class PlaneTest extends WebTestCase
{
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
        yield 'a protocol process serves the JWK Set' => ['protocol', '/jwks', 200];
        yield 'a protocol process leaves the host application alone' => ['protocol', '/host', 200];
        yield 'an interaction process serves the login' => ['interaction', '/login', 200];
        yield 'an interaction process refuses the JWK Set' => ['interaction', '/jwks', 404];
        yield 'an interaction process leaves the host application alone' => ['interaction', '/host', 200];
        yield 'a process serving all planes serves the login' => ['all', '/login', 200];
        yield 'a process serving all planes serves the JWK Set' => ['all', '/jwks', 200];
        yield 'without HEIDI_PLANE a process serves the login' => [null, '/login', 200];
        yield 'without HEIDI_PLANE a process serves the JWK Set' => [null, '/jwks', 200];
        yield 'an unknown path is a 404 on every plane' => ['protocol', '/unknown', 404];
    }

    #[Test]
    #[DataProvider('requests')]
    public function aProcessAnswersTheRoutesOfItsPlaneOnly(?string $plane, string $path, int $status): void
    {
        if ($plane !== null) {
            $_SERVER['HEIDI_PLANE'] = $plane;
        }
        $client = self::createClient();

        $client->request('GET', $path);

        static::assertSame($status, $client->getResponse()->getStatusCode());
    }

    /**
     * A plane that does not exist is not "all": the process refuses to serve at all.
     */
    #[Test]
    public function anUnknownPlaneIsRefused(): void
    {
        $_SERVER['HEIDI_PLANE'] = 'everything';
        $client = self::createClient();
        $client->catchExceptions(false);

        $this->expectException(RuntimeException::class);
        $client->request('GET', '/host');
    }

    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }
}
