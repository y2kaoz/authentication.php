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

use Y2KaoZ\AuthN\Database\TableDefinitions\IdentityRow;
use Y2KaoZ\AuthN\Database\TableDefinitions\IdentityTable;
use Y2KaoZ\Persistence\SQLitePdoDatabase;

class IdentityDatabase extends SQLitePdoDatabase
{
    public IdentityTable $identity;

    private function createRootIdentity(): void
    {
        $rootIdentity = new IdentityRow(["id" => 0, "username" => "root"]);
        $rootIdentity->id = $this->identity->insert($rootIdentity);
        if ($rootIdentity->id === null) {
            $rootIdentity = $this->identity->fetch(["root"], "username")[0] ?? null;
        }
        if ($rootIdentity === null || $rootIdentity->id !== 0) {
            throw new \Exception("Invalid root identity.");
        }
    }

    public function __construct(string $path = ":memory:")
    {
        parent::__construct($path);
        $this->identity = new IdentityTable($this);
    }

    public function createTables(): void
    {
        parent::createTables();
        $this->createRootIdentity();
    }
}
