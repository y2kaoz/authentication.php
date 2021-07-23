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

namespace Y2KaoZ\AuthN\Database;

use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNIdentityTable;
use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNSessionTable;

class Srp6aDatabase extends IdentityDatabase
{
    public Srp6aAuthNIdentityTable $srp6aAuthNIdentity;
    public Srp6aAuthNSessionTable $srp6aAuthNSession;

    public function __construct(string $path = ":memory:")
    {
        parent::__construct($path);
        $this->srp6aAuthNIdentity = new Srp6aAuthNIdentityTable($this, $this->identity);
        $this->srp6aAuthNSession = new Srp6aAuthNSessionTable($this, $this->identity);
    }
}
