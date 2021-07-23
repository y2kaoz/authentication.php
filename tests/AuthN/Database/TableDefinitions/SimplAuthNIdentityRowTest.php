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

namespace Tests\AuthN\Database\TableDefinitions\SimplAuthNIdentityRowTest;

use PHPUnit\Framework\TestCase;
use Y2KaoZ\AuthN\Database\TableDefinitions\SimplAuthNIdentityRow;

class SimplAuthNIdentityRowTest extends TestCase
{
    public function testDefaultConstructor(): void
    {
        $simplAuthNIdentityRow = new SimplAuthNIdentityRow();
        $this->assertNull($simplAuthNIdentityRow->id);
        $this->assertNull($simplAuthNIdentityRow->identityId);
        $this->assertNull($simplAuthNIdentityRow->password);
        $this->assertFalse($simplAuthNIdentityRow->verifyPassword(""));
    }
    public function testFullConstructor(): void
    {
        $simplAuthNIdentityRow = new SimplAuthNIdentityRow([
            "id" => 1,
            "identityId" => 2,
            "password" => "abcd1234"
        ]);
        $this->assertEquals($simplAuthNIdentityRow->id, 1);
        $this->assertEquals($simplAuthNIdentityRow->identityId, 2);
        $this->assertFalse($simplAuthNIdentityRow->password === "abcd1234");
        $this->assertTrue($simplAuthNIdentityRow->verifyPassword("abcd1234"));
    }
    public function testSetNullPasswordAsNull(): void
    {
        $simplAuthNIdentityRow = new SimplAuthNIdentityRow([
            "id" => 1,
            "identityId" => 2,
            "password" => "abcd1234"
        ]);
        $simplAuthNIdentityRow->password = null;
        $this->assertNull($simplAuthNIdentityRow->password);
        $this->assertTrue(isset($simplAuthNIdentityRow->password));
    }
    public function testSetEmptyPasswordAsNull(): void
    {
        $simplAuthNIdentityRow = new SimplAuthNIdentityRow([
            "id" => 1,
            "identityId" => 2,
            "password" => "abcd1234"
        ]);
        $simplAuthNIdentityRow->password = "";
        $this->assertNull($simplAuthNIdentityRow->password);
        $this->assertTrue(isset($simplAuthNIdentityRow->password));
    }
}
