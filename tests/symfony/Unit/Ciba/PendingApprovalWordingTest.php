<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Ciba;

use App\Ciba\PendingApprovalWording;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use DateTimeImmutable;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * CIBA Core §7.1, Architecture §5.7
 */
final class PendingApprovalWordingTest extends TestCase
{
    #[Test]
    public function theTitleNamesTheProviderThatAsks(): void
    {
        // When / Then
        static::assertSame('approval.notice.title{"provider":"Acme"}@fr', self::wording()->title(self::approval(null), 'fr'));
    }

    #[Test]
    public function theSubjectNamesTheProviderThatAsks(): void
    {
        // When / Then
        static::assertSame('approval.notice.subject{"provider":"Acme"}@fr', self::wording()->subject(self::approval(null), 'fr'));
    }

    #[Test]
    public function theBodyNamesTheClientThatAsks(): void
    {
        // When / Then
        static::assertSame('approval.notice.body{"client":"Payment terminal at the counter"}@fr', self::wording()->body(self::approval(null), 'fr'));
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function theBodySaysWhatTheClientWrote(): void
    {
        // When / Then
        static::assertSame(
            'approval.notice.body_with_message{"client":"Payment terminal at the counter","message":"Payment of 42 euros"}@fr',
            self::wording()->body(self::approval(new BindingMessage('Payment of 42 euros')), 'fr'),
        );
    }

    private static function wording(): PendingApprovalWording
    {
        $translator = self::createStub(TranslatorInterface::class);
        $translator
            ->method('trans')
            ->willReturnCallback(
                static fn (string $id, array $parameters = [], ?string $domain = null, ?string $locale = null): string => (
                    $id . json_encode($parameters, JSON_THROW_ON_ERROR) . '@' . $locale
                ),
            );

        return new PendingApprovalWording($translator);
    }

    private static function approval(?BindingMessage $bindingMessage): PendingApproval
    {
        return new PendingApproval(
            Fixtures::tenant(),
            Uuid::v7(),
            'Payment terminal at the counter',
            $bindingMessage,
            new DateTimeImmutable('2026-09-28T09:05:00+00:00'),
            'https://id.acme.example/approvals',
        );
    }
}
