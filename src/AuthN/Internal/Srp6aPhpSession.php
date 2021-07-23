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
use Y2KaoZ\AuthN\Internal\Srp6aSession;

class Srp6aPhpSession extends Srp6aSession
{
    public function __construct(int $expireTime, private string $key = 'srp6a_session')
    {
        parent::__construct($expireTime);
    }
    public function drop(int $identityId, string $publicEphemeralValueA): void
    {
        if (isset($_SESSION[$this->key])) {
            /** @var null|Srp6aAuthNSessionRow $row */
            $row = $_SESSION[$this->key] ?? null;
            if ($row && $row->identityId === $identityId && $row->publicEphemeralValueA === $publicEphemeralValueA) {
                unset($_SESSION[$this->key]);
            }
        }
    }
    public function save(Srp6aAuthNSessionRow $row): int
    {
        $row->expireTimeStamp = time() + $this->expireTime;
        if ($row->identityId === null) {
            throw new \Exception("Unable to save session: invalid identityId.");
        }
        if ($row->publicEphemeralValueA === null) {
            throw new \Exception("Unable to save session: invalid publicEphemeralValueA.");
        }
        $_SESSION[$this->key] = $row;
        return $row->expireTimeStamp;
    }
    public function load(int $identityId, string $publicEphemeralValueA): ?Srp6aAuthNSessionRow
    {
        /** @var null|Srp6aAuthNSessionRow $row */
        $row = $_SESSION[$this->key] ?? null;
        if ($row && $row->identityId === $identityId && $row->publicEphemeralValueA === $publicEphemeralValueA) {
            if ($row->expireTimeStamp === null || $row->expireTimeStamp < time()) {
                $this->drop($identityId, $publicEphemeralValueA);
                return null;
            }
            return $row ;
        }
        return null;
    }
}
