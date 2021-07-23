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

use Y2KaoZ\AuthN\Database\Srp6aDatabase;
use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNSessionRow;
use Y2KaoZ\AuthN\Internal\Srp6aSession;

class Srp6aDbSession extends Srp6aSession
{
    public function __construct(int $expireTime, private Srp6aDatabase $database)
    {
        parent::__construct($expireTime);
    }
    public function drop(int $identityId, string $publicEphemeralValueA): void
    {
        $this->database->srp6aAuthNSession->delete(
            "WHERE identityId=? AND publicEphemeralValueA=?",
            [$identityId, $publicEphemeralValueA]
        );
    }
    public function save(Srp6aAuthNSessionRow $row): int
    {
        $this->database->srp6aAuthNSession->delete("WHERE expireTimeStamp < ?;", [time()]);
        $row->expireTimeStamp = time() + $this->expireTime;
        if ($row->identityId === null) {
            throw new \Exception("Unable to save session: invalid identityId.");
        }
        if ($row->publicEphemeralValueA === null) {
            throw new \Exception("Unable to save session: invalid publicEphemeralValueA.");
        }
        if ($this->load($row->identityId, $row->publicEphemeralValueA) === null) {
            if ($this->database->srp6aAuthNSession->insert($row) === null) {
                throw new \Exception("Unable to insert session row.");
            }
        } else {
            if (!$this->database->srp6aAuthNSession->update($row)) {
                throw new \Exception("Unable to update session row.");
            }
        }
        return $row->expireTimeStamp;
    }
    public function load(int $identityId, string $publicEphemeralValueA): ?Srp6aAuthNSessionRow
    {
        $this->database->srp6aAuthNSession->delete("WHERE expireTimeStamp < ?;", [time()]);
        $row = $this->database->srp6aAuthNSession->fetchAll(
            $this->database->srp6aAuthNSession->select(
                "WHERE identityId=? AND publicEphemeralValueA=?",
                [$identityId, $publicEphemeralValueA]
            )
        )[0] ?? null;
        if ($row && $row->identityId === $identityId && $row->publicEphemeralValueA === $publicEphemeralValueA) {
            if ($row->expireTimeStamp === null || $row->expireTimeStamp < time()) {
                $this->drop($identityId, $publicEphemeralValueA);
                return null;
            }
            return $row;
        }
        return null;
    }
}
