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

namespace Y2KaoZ\AuthN\Internal;

use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNSessionRow;

abstract class Srp6aSession
{
    protected function isValidRow(Srp6aAuthNSessionRow $row, int $identityId, string $publicEphemeralValueA): bool
    {
        if ($row->expireTimeStamp === null || $row->expireTimeStamp < time()) {
            return false;
        }
        if ($row->identityId === null || $row->identityId !== $identityId) {
            return false;
        }
        if ($row->publicEphemeralValueA === null || $row->publicEphemeralValueA !== $publicEphemeralValueA) {
            return false;
        }
        return true;
    }
    public function __construct(protected int $expireTime)
    {
    }
    public function bump(int $identityId, string $publicEphemeralValueA): ?int
    {
        $row = $this->load($identityId, $publicEphemeralValueA);
        if ($row !== null) {
            $row->expireTimeStamp = time() + $this->expireTime;
            return $this->save($row);
        }
        return null;
    }
    abstract public function drop(int $identityId, string $publicEphemeralValueA): void;
    abstract public function save(Srp6aAuthNSessionRow $row): int;
    abstract public function load(int $identityId, string $publicEphemeralValueA): ?Srp6aAuthNSessionRow;
}
