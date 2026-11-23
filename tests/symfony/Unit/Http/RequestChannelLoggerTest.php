<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\RequestChannelLogger;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

/**
 * Decision 0026
 */
final class RequestChannelLoggerTest extends TestCase
{
    private const string TICKET = '0193c3a1-0000-7000-8000-000000000001';

    private const string VALUE = 'q8Z5yT0n3k1m4Vb7Xx2LpR9sWd6Fh0Jc3Gt8Ue5Ai1o';

    private RecordingLogger $recorded;

    private RequestChannelLogger $logger;

    protected function setUp(): void
    {
        $this->recorded = new RecordingLogger();
        $this->logger = new RequestChannelLogger($this->recorded);
    }

    #[Test]
    public function theValueOfATicketIsWithheldFromTheParametersOfItsRoute(): void
    {
        // When
        $this->logger->info('Matched route "{route}".', self::matched('/enrol/' . self::TICKET . '/' . self::VALUE));

        // Then
        static::assertSame(
            [
                '_route' => 'beffroi_interaction_enrolment_ticket',
                'ticket' => self::TICKET,
                'value' => RequestChannelLogger::WITHHELD,
            ],
            $this->recorded->records[0]['context']['route_parameters'] ?? null,
        );
    }

    #[Test]
    public function theValueOfATicketIsWithheldFromThePathOfTheUri(): void
    {
        // When
        $this->logger->info('Matched route "{route}".', self::matched('/enrol/' . self::TICKET . '/' . self::VALUE . '/options'));

        // Then
        static::assertSame(
            'https://op.example/enrol/' . self::TICKET . '/REDACTED/options',
            $this->recorded->records[0]['context']['request_uri'] ?? null,
        );
    }

    #[Test]
    public function theQueryKeepsTheNamesOfItsParametersAndNoneOfTheirValues(): void
    {
        // When
        $this->logger->info('Matched route "{route}".', [
            'route' => 'beffroi_interaction_authorize',
            'route_parameters' => ['_route' => 'beffroi_interaction_authorize'],
            'request_uri' => 'https://op.example/authorize?client_id=a&id_token_hint=eyJhbGciOi.eyJzdWIiOiJhbGljZSJ9.sig&login_hint=alice%40example.com',
            'method' => 'GET',
        ]);

        // Then
        static::assertSame(
            'https://op.example/authorize?client_id=REDACTED&id_token_hint=REDACTED&login_hint=REDACTED',
            $this->recorded->records[0]['context']['request_uri'] ?? null,
        );
    }

    #[Test]
    public function aRecordThatNamesNoRequestIsWrittenAsItCame(): void
    {
        // When
        $this->logger->critical('Uncaught PHP Exception {class}', ['class' => 'RuntimeException']);

        // Then
        static::assertSame(
            [
                'level' => LogLevel::CRITICAL,
                'message' => 'Uncaught PHP Exception {class}',
                'context' => ['class' => 'RuntimeException'],
            ],
            $this->recorded->records[0] ?? null,
        );
    }

    /**
     * What Symfony's RouterListener writes once it matched a route.
     *
     * @return array<string, mixed>
     */
    private static function matched(string $path): array
    {
        return [
            'route' => 'beffroi_interaction_enrolment_ticket',
            'route_parameters' => [
                '_route' => 'beffroi_interaction_enrolment_ticket',
                'ticket' => self::TICKET,
                'value' => self::VALUE,
            ],
            'request_uri' => 'https://op.example' . $path,
            'method' => 'GET',
        ];
    }
}
