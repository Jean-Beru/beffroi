<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use App\Command\UserEnrolmentTicketCommand;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #841: the link of an enrolment ticket on a deployment whose issuer has a path, the routes of the provider
 * mounted under it as RouterEndpointLocator requires (config_test_issuer_with_a_path.yml). The path the router
 * generates for a route already carries that prefix, so the link is the origin of the issuer followed by it,
 * never the issuer followed by it.
 */
final class EnrolmentTicketUnderAPathTest extends ConsoleTestCase
{
    /**
     * The environment whose issuer has a path.
     */
    private const string ISSUER_WITH_A_PATH = 'test_issuer_with_a_path';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::ISSUER_WITH_A_PATH,
        ];
    }

    #[Test]
    public function theLinkItPrintsOpensThePageOfThatEnrolment(): void
    {
        // Given
        self::user('alice');

        // When
        $link = self::displayed(self::console(UserEnrolmentTicketCommand::NAME, [
            'username' => 'alice',
        ]), 'Link');

        // Then
        static::assertStringStartsWith('https://op.test/idp/enrol/', $link);
        $this->browser->request('GET', $link);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }
}
