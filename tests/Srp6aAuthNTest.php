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

namespace Tests\AuthN\Srp6aAuthNTest;

use PHPUnit\Framework\TestCase;
use Y2KaoZ\AuthN\Database\Srp6aDatabase;
use Y2KaoZ\AuthN\Srp6a;
use Y2KaoZ\AuthN\Srp6aAuthN;
use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNIdentityRow;

class Srp6aAuthNTest extends TestCase
{
    private const SAFE_PRIME = "0x00a8e482713948ef5e9b05cf1042903b23ef828252450c1e3c84a2f16416f39b49810de4a41b2159f2c2efbff73210ff58f6f5087fd60f924eefb7482147bf4d137bb3890c9d5272f4f2f9582530389a02b1d0785d435f029a54e8364c5b174f4fc96ce7518d53e4c4070e82e7ac600bbcba4ad3cbf7913a11c3eee4b4ad841593";
    private const GENERATOR_MODULO = "0x2";
    protected Srp6aDatabase $database;
    protected Srp6a $srp6a;

    public function setUp(): void
    {
        $this->database = new Srp6aDatabase();
        $this->database->createTables();
        $this->srp6a = new Srp6a(self::SAFE_PRIME, self::GENERATOR_MODULO);
    }

    public function tearDown(): void
    {
        $this->database->dropTables();
    }

    public function testInvalidUsername(): void
    {
        $srp6aAuthN = new Srp6aAuthN($this->srp6a, $this->database);
        $this->assertNull($srp6aAuthN->authenticateChallenge("InvalidUsername", "1234"));
        $this->assertNull($srp6aAuthN->loadSession("InvalidUsername", "1234"));
    }

    public function testFirstAuthentication(): void
    {
        $rootId = 0;
        $srp6aAuthN = new Srp6aAuthN($this->srp6a, $this->database);
        $srp6aAuthNIdentityRow = $this->database->srp6aAuthNIdentity->fetch([$rootId], "identityId");
        $this->assertCount(1, $srp6aAuthNIdentityRow);
        $this->assertNull($srp6aAuthNIdentityRow[0]);
        $id = $srp6aAuthN->authenticateChallenge("root", "1234");
        $this->assertNull($id);
        $this->assertNull($srp6aAuthN->loadSession("root", "1234"));
    }

    public function testUpgradeInvalidUser(): void
    {
        $rootId = 0;
        $srp6aAuthN = new Srp6aAuthN($this->srp6a, $this->database);
        $srp6aAuthNIdentityRow = $this->database->srp6aAuthNIdentity->fetch([$rootId], "identityId");
        $this->assertCount(1, $srp6aAuthNIdentityRow);
        $this->assertNull($srp6aAuthNIdentityRow[0]);
        $id = $srp6aAuthN->upgrade("InvalidUsername", "password");
        $this->assertNull($id);
    }

    public function testUpgradeValidUser(): void
    {
        $rootId = 0;
        $srp6aAuthN = new Srp6aAuthN($this->srp6a, $this->database);
        $srp6aAuthNIdentityRow = $this->database->srp6aAuthNIdentity->fetch([$rootId], "identityId");
        $this->assertCount(1, $srp6aAuthNIdentityRow);
        $this->assertNull($srp6aAuthNIdentityRow[0]);
        $id = $srp6aAuthN->upgrade("root", "validPassword");
        $this->assertIsInt($id);
        $this->assertEquals($id, $rootId);
        $id = $srp6aAuthN->fallback("root", "validPassword");
        $this->assertIsInt($id);
        $this->assertEquals($id, $rootId);
    }

    public function testInvalidPassword(): void
    {
        $rootId = 0;
        $srp6aAuthN = new Srp6aAuthN($this->srp6a, $this->database);
        $id = $srp6aAuthN->upgrade("root", "validPassword");
        $this->assertIsInt($id);
        $this->assertEquals($id, $rootId);
        $this->assertNull($srp6aAuthN->fallback("root", "invalidPassword"));
    }
}
