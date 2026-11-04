<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\ResponseMode;

use App\Http\ResponseMode\SignsTheAnswerInterface;

/**
 * JARM §2
 */
final class FakeSigningRenderer extends FakeResponseModeRenderer implements SignsTheAnswerInterface
{
}
