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

namespace Y2KaoZ\AuthN;

use Y2KaoZ\AuthN\Database\SimplDatabase;
use Y2KaoZ\AuthN\Database\TableDefinitions\SimplAuthNIdentityRow;

class SimplAuthN
{
    public function __construct(private SimplDatabase $database)
    {
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $password */
    public function authenticate(string $username, string $password): ?int
    {
        $identity = $this->database->identity->fetch([$username], "username")[0] ?? null;
        if ($identity === null || $identity->id === null) {
            return null;
        }

        $simplAuthNIdentity = $this->database->simplAuthNIdentity->fetch([$identity->id], "identityId")[0] ?? null;
        if ($simplAuthNIdentity === null) {
            $simplAuthNIdentity = new SimplAuthNIdentityRow(["identityId" => $identity->id, "password" => $password]);
            $simplAuthNIdentity->id = $this->database->simplAuthNIdentity->insert($simplAuthNIdentity);
            if ($simplAuthNIdentity->id === null) {
                throw new \Exception("Unable to create simple authenticator identity for '$username'.");
            }
        }

        if ($simplAuthNIdentity->password === null) {
            $simplAuthNIdentity->password = $password;
            $updated = $this->database->simplAuthNIdentity->update($simplAuthNIdentity);
            if (!$updated) {
                throw new \Exception("Unable to create simple password for '$username'.");
            }
        }

        return $simplAuthNIdentity->verifyPassword($password) ? $identity->id : null;
    }
}
