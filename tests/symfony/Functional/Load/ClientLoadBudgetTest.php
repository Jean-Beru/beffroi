<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Load;

use function base64_encode;
use App\Load\LoadBudget;
use App\Load\LoadRefusal;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0014, RFC 6749 §4.4
 */
final class ClientLoadBudgetTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'service-app';

    private const string SECRET = 'service-secret-of-at-least-32-characters-l';

    private const string OTHER_CLIENT_ID = 'service-opaque-app';

    private const string OTHER_SECRET = 'service-opaque-secret-of-at-least-32-chars';

    /**
     * RFC 8628 §3.1
     */
    private const string PUBLIC_CLIENT_ID = 'appliance-public-app';

    private const string CALENDAR = 'https://cal.example.com/';

    private const int BUDGET = 1;

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_CLIENT_BUDGET'] = (string) self::BUDGET;
        parent::setUp();
        $this->browser->disableReboot();
        self::signingKey();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_CLIENT_BUDGET'], $_ENV['BEFFROI_TEST_CLIENT_BUDGET']);
    }

    /**
     * Decision 0014, RFC 6585 §4
     */
    #[Test]
    public function aClientPastItsBudgetIsRefused(): void
    {
        // Given
        $this->spendTheBudgetOf(self::CLIENT_ID, self::SECRET);

        // When
        $this->ask(self::CLIENT_ID, self::SECRET);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_TOO_MANY_REQUESTS, $response->getStatusCode());
        static::assertGreaterThan(0, (int) $response->headers->get('Retry-After'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        $members = self::json($response);
        static::assertArrayNotHasKey('error', $members);
        static::assertSame(LoadRefusal::DESCRIPTION, $members['error_description']);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function theBudgetIsCountedByClient(): void
    {
        // Given
        $this->spendTheBudgetOf(self::CLIENT_ID, self::SECRET);

        // When
        $this->ask(self::OTHER_CLIENT_ID, self::OTHER_SECRET);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aClientThatOnlyNamesItselfTakesNothingOfTheBudget(): void
    {
        // Given
        $refused = [];

        // When
        for ($attempt = 1; $attempt <= (self::BUDGET + 1); ++$attempt) {
            $this->browser->request('POST', '/token', [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code' => 'not-a-device-code-of-this-provider',
                'client_id' => self::PUBLIC_CLIENT_ID,
            ]);
            $refused[] = self::string(self::json($this->browser->getResponse())['error']);
        }

        // Then
        static::assertSame(['invalid_grant', 'invalid_grant'], $refused);
    }

    /**
     * Decision 0014
     */
    #[Test]
    public function aRefusalReachesTheAuditTrailWithItsClient(): void
    {
        // Given
        $this->spendTheBudgetOf(self::CLIENT_ID, self::SECRET);

        // When
        $this->ask(self::CLIENT_ID, self::SECRET);

        // Then
        $spent = self::refusals();
        static::assertCount(1, $spent);
        static::assertSame(LoadBudget::CLIENT, $spent[0]->budget);
        static::assertSame('beffroi_protocol_token', $spent[0]->route);
        static::assertSame(self::CLIENT_ID, $spent[0]->client);
    }

    private function spendTheBudgetOf(string $clientId, string $secret): void
    {
        for ($request = 1; $request <= self::BUDGET; ++$request) {
            $this->ask($clientId, $secret);
            static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
        }
    }

    private function ask(string $clientId, string $secret): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => self::CALENDAR,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ],
        );
    }

    /**
     * @return list<LoadBudgetSpent>
     */
    private static function refusals(): array
    {
        $refusals = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LoadBudgetSpent) {
                $refusals[] = $event;
            }
        }

        return $refusals;
    }
}
