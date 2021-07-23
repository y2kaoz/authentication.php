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

use Y2KaoZ\Common\CopyProperties;
use Y2KaoZ\Persistence\Attributes\ColumnConstraints;
use Y2KaoZ\Persistence\Interfaces\TableRowInterface;
use Y2KaoZ\Persistence\Traits\TableRowTrait;

class Srp6aAuthNIdentityRow
{
    #[ColumnConstraints(['PRIMARY KEY'])]
    public ?int $id = null;
    #[ColumnConstraints(["UNIQUE", "NOT NULL"]), ColumnForeignKey("identity", "id", "CASCADE", "CASCADE")]
    public ?int $identityId = null;
    #[ColumnConstraints(["UNIQUE", "NOT NULL"])]
    public ?string $salt = null;
    #[ColumnConstraints(["UNIQUE", "NOT NULL"])]
    public ?string $passwordVerifier = null;

    /** @param null|self|array<string,?scalar> $source */
    public function __construct(null|self|array $source = null)
    {
        if ($source !== null) {
            if (is_array($source)) {
                CopyProperties::fromArray($this, $source);
            } else {
                CopyProperties::fromObject($this, $source);
            }
        }
    }
}
