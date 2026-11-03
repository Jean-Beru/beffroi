<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\ResponseMode;

use App\Http\ResponseMode\AnswersTheJwtAliasInterface;

/**
 * The way of answering "response_mode=jwt" resolves to (JARM §2.1).
 */
final class FakeAliasedRenderer extends FakeResponseModeRenderer implements AnswersTheJwtAliasInterface
{
}
