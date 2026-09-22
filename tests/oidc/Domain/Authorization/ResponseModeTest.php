<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Oidc\Domain\Authorization\ResponseMode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 and JARM §2.1: the closed set of modes the
 * specifications fix, and the one of them that names another.
 */
final class ResponseModeTest extends TestCase
{
    /**
     * JARM §2.1: "jwt" is the signed mode the response type defaults to, which for "code", the only
     * response type this provider serves, is "query.jwt".
     */
    #[Test]
    public function theJwtModeNamesTheSignedQueryOfTheCodeResponseType(): void
    {
        // When / Then
        static::assertSame(ResponseMode::QueryJwt, ResponseMode::Jwt->resolved());
    }

    /**
     * Every mode that delivers names itself, so that a request is judged against what will answer it.
     */
    #[Test]
    #[DataProvider('provideDeliveringModes')]
    public function aModeThatDeliversResolvesToItself(ResponseMode $mode): void
    {
        // When / Then
        static::assertSame($mode, $mode->resolved());
    }

    /**
     * @return iterable<string, array{ResponseMode}>
     */
    public static function provideDeliveringModes(): iterable
    {
        yield 'query' => [ResponseMode::Query];
        yield 'form_post' => [ResponseMode::FormPost];
        yield 'query.jwt' => [ResponseMode::QueryJwt];
        yield 'form_post.jwt' => [ResponseMode::FormPostJwt];
    }

    /**
     * JARM §2: what makes the answer a JWS the tenant signs, and what a key retirement accounts for.
     */
    #[Test]
    #[DataProvider('provideModes')]
    public function aModeSaysWhetherTheAnswerIsSigned(ResponseMode $mode, bool $signed): void
    {
        // When / Then
        static::assertSame($signed, $mode->signsTheAnswer());
    }

    /**
     * @return iterable<string, array{ResponseMode, bool}>
     */
    public static function provideModes(): iterable
    {
        yield 'query' => [ResponseMode::Query, false];
        yield 'form_post' => [ResponseMode::FormPost, false];
        yield 'jwt' => [ResponseMode::Jwt, true];
        yield 'query.jwt' => [ResponseMode::QueryJwt, true];
        yield 'form_post.jwt' => [ResponseMode::FormPostJwt, true];
    }
}
