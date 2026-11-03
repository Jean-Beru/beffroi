<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\ResponseMode;

use App\Http\ResponseMode\SignsTheAnswerInterface;

/**
 * A way of answering whose answer is a document the tenant signs (JARM §2), and which the alias does not
 * resolve to.
 */
final class FakeSigningRenderer extends FakeResponseModeRenderer implements SignsTheAnswerInterface
{
}
