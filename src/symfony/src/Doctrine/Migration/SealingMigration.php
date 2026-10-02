<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Migration;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use function implode;
use function is_numeric;
use function sprintf;

/**
 * A migration that seals the columns of a table, and the two things every one of them has to say before it
 * runs (decisions 0011 and 0018).
 *
 * A sealed column is binary and accepts no null, so a table that holds rows whose values are in the clear
 * cannot be migrated: the column it recreates comes back refusing the nulls the rows would leave, and the
 * server stops. That refusal is intended, there being **no migration path for cleartext rows** and no
 * deployment to need one; what is not intended is for the operator to read a null violation on a column
 * nobody made nullable, with nothing about what to do next.
 *
 * So the check happens here, in `preUp()`, which the executor of the migrations calls before `up()`
 * (`DbalExecutor`). Nothing of the functional suite calls it, `MigrationTest` instantiating each migration
 * and calling `up()` alone, which is what lets that test compare the DDL of every migration with the
 * mappings without a database at all.
 *
 * The second thing is what no migration can do for the operator: a process that booted before this one
 * holds the type registry it built then, so it reads these columns with the type they had, and what it does
 * then depends on which type that was. A column typed `string` throws, pdo_pgsql handing a blob back as a
 * stream that `StringType` passes on untouched; a column typed `text` does not, `TextType` reading the
 * stream and returning the raw ciphertext as a string for its caller to act on. That one is the reason the
 * sentence exists: nothing says anything, and the failure surfaces wherever the value was going. So the
 * migration says to restart what serves and what consumes, which is the only way out, and says it whether
 * the column seals or unseals, both being a change of type.
 *
 * What a migration of this kind still carries itself is the platform it is written for: the check below is
 * a count and runs anywhere, the statements are PostgreSQL and say so.
 *
 * **It lives here and not beside the migrations** because `src/symfony/migrations/` is in the `autoload` of
 * no package: the bundle declares that directory to Doctrine Migrations, which loads the version files it
 * finds there and nothing else, and only the `autoload-dev` of the monorepo maps the namespace, so a class
 * placed there resolves in the suite and not in a deployment.
 */
abstract class SealingMigration extends AbstractMigration
{
    public function preUp(Schema $schema): void
    {
        $this->refuseRowsIn('seals');
        $this->sayToRestartWhatReadsTheColumns();
    }

    /**
     * Going back is refused for the same reason and not the opposite one: nothing here unseals a value, so
     * a row would come back out of a column that no longer holds its ciphertext.
     */
    public function preDown(Schema $schema): void
    {
        $this->refuseRowsIn('unseals');
        $this->sayToRestartWhatReadsTheColumns();
    }

    /**
     * The tables this migration recreates columns of, which therefore have to be empty.
     *
     * @return list<string>
     */
    abstract protected function tablesToSeal(): array;

    /**
     * Said once the rows are accounted for, so that a migration that goes no further says what stops it and
     * nothing else, and said in the terms of the schema rather than of a deployment: what serves and what
     * consumes is a process list this class cannot know.
     */
    private function sayToRestartWhatReadsTheColumns(): void
    {
        $this->write(sprintf(
            'A process that booted before this migration reads the columns of %s with the type they had, so restart what serves requests and what consumes the bus once it has run. A column typed "string" throws, a blob coming back as a stream; a column typed "text" does not, and returns the ciphertext as a string for its caller to act on, which nothing reports.',
            implode(', ', $this->tablesToSeal()),
        ));
    }

    private function refuseRowsIn(string $what): void
    {
        foreach ($this->tablesToSeal() as $table) {
            // A count that does not come back as a number is left to the server rather than guessed at:
            // what this adds is a sentence, and it never decides on its own that a table is empty.
            $count = $this->connection->fetchOne(sprintf('SELECT COUNT(*) FROM %s', $table));
            $rows = is_numeric($count) ? (int) $count : 0;

            $this->abortIf($rows > 0, sprintf(
                '%s holds %d row(s) and this migration %s its columns, which recreates them: a sealed column is binary and accepts no null, so there is nothing to put in the rows that are there. There is no migration path for cleartext rows and no deployment that would need one (decision 0011). Seal them with a script of your own, or empty the table ("TRUNCATE TABLE %s CASCADE" on a development stack, which "castor provision" then fills again).',
                $table,
                $rows,
                $what,
                $table,
            ));
        }
    }
}
