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

namespace Tests\AuthN\SimplAuthNTest;

use PHPUnit\Framework\TestCase;
use Y2KaoZ\AuthN\Database\SimplDatabase;
use Y2KaoZ\AuthN\SimplAuthN;
use Y2KaoZ\AuthN\Database\TableDefinitions\SimplAuthNIdentityRow;

class SimplAuthNTest extends TestCase
{
    protected SimplDatabase $database;
    public function setUp(): void
    {
        $this->database = new SimplDatabase();
        $this->database->createTables();
    }

    public function tearDown(): void
    {
        $this->database->dropTables();
    }

    public function testInvalidUsername(): void
    {
        $simplAuthN = new SimplAuthN($this->database);
        $this->assertNull($simplAuthN->authenticate("InvalidUsername", "InvalidPassword"));
    }

    public function testFirstAuthentication(): void
    {
        $rootId = 0;
        $simplAuthN = new SimplAuthN($this->database);
        $simplAuthNIdentityRow = $this->database->simplAuthNIdentity->fetch([$rootId], "identityId");
        $this->assertCount(1, $simplAuthNIdentityRow);
        $this->assertNull($simplAuthNIdentityRow[0]);
        $id = $simplAuthN->authenticate("root", "1234");
        $this->assertIsInt($id);
        $this->assertEquals($id, $rootId);
        $simplAuthNIdentityRow = $this->database->simplAuthNIdentity->fetch([$id], "identityId");
        $this->assertCount(1, $simplAuthNIdentityRow);
        $this->assertInstanceOf(SimplAuthNIdentityRow::class, $simplAuthNIdentityRow[0]);
        $this->assertEquals($simplAuthNIdentityRow[0]->id, 1);
        $this->assertEquals($simplAuthNIdentityRow[0]->identityId, $id);
        $this->assertFalse($simplAuthNIdentityRow[0]->password === "1234");
        $this->assertTrue($simplAuthNIdentityRow[0]->verifyPassword("1234"));
    }

    public function testInvalidPassword(): void
    {
        $rootId = 0;
        $simplAuthN = new SimplAuthN($this->database);
        $id = $simplAuthN->authenticate("root", "ValidPassword");
        $this->assertIsInt($id);
        $this->assertEquals($id, $rootId);
        $this->assertNull($simplAuthN->authenticate("root", "InvalidPassword"));
    }
}
