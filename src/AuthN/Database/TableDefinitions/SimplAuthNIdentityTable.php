<?php

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

declare(strict_types=1);

namespace Y2KaoZ\AuthN\Database\TableDefinitions;

use Y2KaoZ\Persistence\Attributes\ColumnForeignKey;
use Y2KaoZ\Persistence\Database;
use Y2KaoZ\Persistence\Table;
use Y2KaoZ\Persistence\TableDefinition;

/** @extends Table<SimplAuthNIdentityRow> */
class SimplAuthNIdentityTable extends Table
{
    /** @param non-empty-string $tablename */
    public function __construct(
        Database $database,
        private IdentityTable $identityTable,
        string $tablename = "simplAuthNIdentity"
    ) {
        $overrides = [ "identityId" => new ColumnForeignKey(
            $identityTable->getTableDefinition()->getTableName(),
            "id",
            "CASCADE",
            "CASCADE"
        ) ];
        parent::__construct($database, new TableDefinition($tablename, SimplAuthNIdentityRow::class, $overrides));
    }
}
