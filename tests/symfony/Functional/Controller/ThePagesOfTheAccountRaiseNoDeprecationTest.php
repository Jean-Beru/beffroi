<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Closure;
use Doctrine\Deprecations\Deprecation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #907: what a page of the account reads, it reads in an order, and doctrine/orm deprecates an order
 * whose direction its query builder is handed as a string rather than as a \SortDirection. A deployment reads
 * that deprecation on its "deprecation" channel, where a process writes it the first time it orders a query
 * that way. The browser of these tests is signed in.
 */
final class ThePagesOfTheAccountRaiseNoDeprecationTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->signIn(self::user('alice'));
    }

    #[Test]
    #[DataProvider('provideThePagesOfTheAccount')]
    public function aPageOfTheAccountRaisesNoDeprecationOfDoctrine(string $page): void
    {
        // When
        $deprecations = self::doctrineDeprecationsRaisedWhile(fn (): object => $this->browser->request('GET', $page));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideThePagesOfTheAccount(): iterable
    {
        yield 'the home of the account' => ['/account'];
        yield 'the acts' => ['/account/acts'];
        yield 'the requests waiting' => ['/account/approvals'];
        yield 'the archive' => ['/account/archive'];
        yield 'the consents' => ['/account/consents'];
        yield 'the notifications' => ['/account/notifications'];
        yield 'the passkeys' => ['/account/passkeys'];
        yield 'the password' => ['/account/password'];
        yield 'the profile' => ['/account/profile'];
        yield 'the changes of the profile' => ['/account/profile/changes'];
        yield 'the sessions' => ['/account/sessions'];
        yield 'the two-factor authentication' => ['/account/two-factor'];
    }

    /**
     * How many times each deprecation of Doctrine was raised while the call ran, by its identifier. Doctrine
     * counts every one and raises it once in a process, so the count is what is read: a page read after
     * another that ordered its rows the same way would otherwise raise nothing.
     *
     * @param Closure(): mixed $call
     *
     * @return array<string, int>
     */
    private static function doctrineDeprecationsRaisedWhile(Closure $call): array
    {
        // counted whatever DOCTRINE_DEPRECATIONS says: Doctrine reads it at the first deprecation of the
        // process, which may come before any kernel booted, and FrameworkBundle sets it when one does
        Deprecation::enableTrackingDeprecations();
        $before = Deprecation::getTriggeredDeprecations();
        $call();
        $raised = [];
        foreach (Deprecation::getTriggeredDeprecations() as $identifier => $count) {
            $times = $count - ($before[$identifier] ?? 0);
            if ($times > 0) {
                $raised[$identifier] = $times;
            }
        }

        return $raised;
    }
}
