<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

/**
 * The one way of answering that "response_mode=jwt" resolves to (JARM §2.1): the alias delivers nothing of
 * its own and names the signed mode the response type defaults to, which for "code", the only response type
 * this provider serves (decision 0006), is the one that delivers in the query of the redirect URI.
 *
 * It is declared here and not compared anywhere: a deployment that wires no such way of answering serves no
 * alias, and one that wires two is a wiring with two answers to one question, which is refused.
 */
interface AnswersTheJwtAliasInterface extends SignsTheAnswerInterface
{
}
