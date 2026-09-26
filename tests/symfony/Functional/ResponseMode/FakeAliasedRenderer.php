<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\ResponseMode;

use Heidi\Bundle\Http\ResponseMode\AnswersTheJwtAliasInterface;

/**
 * The way of answering "response_mode=jwt" resolves to (JARM §2.1).
 */
final class FakeAliasedRenderer extends FakeResponseModeRenderer implements AnswersTheJwtAliasInterface
{
}
