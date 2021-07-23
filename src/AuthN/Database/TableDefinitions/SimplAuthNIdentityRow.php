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

class SimplAuthNIdentityRow implements TableRowInterface
{
    use TableRowTrait;

    #[ColumnConstraints(['PRIMARY KEY'])]
    public ?int $id = null;
    #[ColumnConstraints(["UNIQUE", "NOT NULL"]), ColumnForeignKey("identity", "id", "CASCADE", "CASCADE")]
    public ?int $identityId = null;
    #[ColumnConstraints(["UNIQUE", "CHECK (password IS NULL OR length(password) > 0)"])]
    private ?string $password = null;

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

    public function __set(string $name, ?string $value): void
    {
        if ($name === "password") {
            $this->password = $value === null || empty(trim($value)) ? null : $this->hashPassword($value);
        }
    }

    public function __get(string $name): ?string
    {
        return $name === "password" ? $this->password : null;
    }

    public function __isset(string $name): bool
    {
        return $name === "password" ? true : false;
    }

    public function __unset(string $name): void
    {
        if ($name === "password") {
            $this->password = null;
        }
    }

    public function verifyPassword(string $password): bool
    {
        return !is_null($this->password) ? password_verify($password, $this->password) : false;
    }

    public function hashPassword(string $password): string
    {
        $password = trim($password);
        if (empty($password)) {
            throw new \Exception("The password cannot be empty");
        }
        $password_info = password_get_info($password);
        if (!array_key_exists("algo", $password_info) || is_null($password_info["algo"])) {
            $password = password_hash($password, PASSWORD_DEFAULT);
            if (!$password) {
                throw new \Exception("password_hash has failed.");
            }
        }
        return $password;
    }
}
