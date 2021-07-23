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

use Y2KaoZ\AuthN\Database\Srp6aDatabase;
use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNIdentityRow;
use Y2KaoZ\AuthN\Database\TableDefinitions\Srp6aAuthNSessionRow;
use Y2KaoZ\AuthN\Srp6a;
use Y2KaoZ\AuthN\Internal\Srp6aDbSession;
use Y2KaoZ\AuthN\Internal\Srp6aPhpSession;
use Y2KaoZ\AuthN\Internal\Srp6aSession;

class Srp6aAuthN
{
    private Srp6aSession $sessionLogic;

    /** @param non-empty-string $username */
    private function getSrp6aAuthNIdentity(string $username): ?Srp6aAuthNIdentityRow
    {
        $identity = $this->database->identity->fetch([$username], "username")[0] ?? null;
        if ($identity === null || $identity->id === null) {
            return null;
        }
        $srp6aAuthNIdentity = $this->database->srp6aAuthNIdentity->fetch([$identity->id], "identityId")[0] ?? null;
        return $srp6aAuthNIdentity;
    }

    public function __construct(private Srp6a $srp6a, private Srp6aDatabase $database, int $expireTime = 600)
    {
        if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_ACTIVE) {
            $this->sessionLogic = new Srp6aPhpSession($expireTime);
        } else {
            $this->sessionLogic = new Srp6aDbSession($expireTime, $database);
        }
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $publicEphemeralValueA
     * @return null|array{expire:int,salt:string,publicEphemeralValueB:numeric-string}*/
    public function authenticateChallenge(string $username, string $publicEphemeralValueA): ?array
    {
        if (!$this->srp6a->validatePublicEphemeralValue(gmp_init($publicEphemeralValueA, 16))) {
            throw new \Exception("Invalid Public Ephemeral Value A.");
        }

        $srp6aAuthNIdentity = $this->getSrp6aAuthNIdentity($username);
        if (
            $srp6aAuthNIdentity === null ||
            $srp6aAuthNIdentity->identityId === null ||
            $srp6aAuthNIdentity->salt === null ||
            $srp6aAuthNIdentity->passwordVerifier === null
        ) {
            return null;
        }

        $session = $this->sessionLogic->load($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
        if ($session !== null) {
            $this->sessionLogic->drop($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
        }

        $secretEphemeralValueB = $this->srp6a->generateSecretEphemeralValue();
        $publicEphemeralValueB = $this->srp6a->calcPublicEphemeralValueB(
            gmp_init($srp6aAuthNIdentity->passwordVerifier, 16),
            $secretEphemeralValueB
        );

        if (!$this->srp6a->validatePublicEphemeralValue($publicEphemeralValueB)) {
            throw new \Exception("Invalid Public Ephemeral Value B.");
        }

        $expireTimeStamp = $this->sessionLogic->save(new Srp6aAuthNSessionRow([
            'identityId' => $srp6aAuthNIdentity->identityId,
            'publicEphemeralValueA' => $publicEphemeralValueA,
            'secretEphemeralValueB' => gmp_strval($secretEphemeralValueB, 16),
            'publicEphemeralValueB' => gmp_strval($publicEphemeralValueB, 16)
        ]));

        return [
            "expire" => $expireTimeStamp,
            "salt" => $srp6aAuthNIdentity->salt,
            "publicEphemeralValueB" => gmp_strval($publicEphemeralValueB, 16)
        ];
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $publicEphemeralValueA
     * @param non-empty-string $clientKeyMatchProof */
    public function authenticateProof(string $username, string $publicEphemeralValueA, string $clientKeyMatchProof): ?string
    {
        if (!$this->srp6a->validatePublicEphemeralValue(gmp_init($publicEphemeralValueA, 16))) {
            throw new \Exception("Invalid Public Ephemeral Value A.");
        }
        $srp6aAuthNIdentity = $this->getSrp6aAuthNIdentity($username);
        if (
            $srp6aAuthNIdentity === null ||
            $srp6aAuthNIdentity->identityId === null ||
            $srp6aAuthNIdentity->salt === null ||
            $srp6aAuthNIdentity->passwordVerifier === null
        ) {
            return null;
        }
        $passwordVerifier = gmp_init($srp6aAuthNIdentity->passwordVerifier, 16);
        $session = $this->sessionLogic->load($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
        if (
            $session === null ||
            $session->publicEphemeralValueA === null ||
            $session->secretEphemeralValueB === null ||
            $session->publicEphemeralValueB === null
        ) {
            return null;
        }
        $publicEphemeralValueA = gmp_init($session->publicEphemeralValueA, 16);
        $secretEphemeralValueB = gmp_init($session->secretEphemeralValueB, 16);
        $publicEphemeralValueB = gmp_init($session->publicEphemeralValueB, 16);
        if (!$this->srp6a->validatePublicEphemeralValue($publicEphemeralValueB)) {
            throw new \Exception("Invalid Public Ephemeral Value B.");
        }

        $randomScramblingParameter = $this->srp6a->calcRandomScramblingParameter(
            $publicEphemeralValueA,
            $publicEphemeralValueB
        );
        $session->randomScramblingParameter = gmp_strval($randomScramblingParameter, 16);

        $serverSessionKey = $this->srp6a->calcServerSessionKey(
            $publicEphemeralValueA,
            $passwordVerifier,
            $randomScramblingParameter,
            $secretEphemeralValueB
        );
        $session->serverSessionKey = gmp_strval($serverSessionKey, 16);

        $key = $this->srp6a->calcKey($serverSessionKey);
        $session->key = gmp_strval($key, 16);

        $clientKeyMatchTest = $this->srp6a->calcClientKeyMatch(
            $username,
            gmp_init($srp6aAuthNIdentity->salt, 16),
            $publicEphemeralValueA,
            $publicEphemeralValueB,
            $key
        );

        if ($clientKeyMatchProof === gmp_strval($clientKeyMatchTest, 16)) {
            $keyMatchProof = $this->srp6a->calcServerKeyMatch(
                $publicEphemeralValueA,
                gmp_init($clientKeyMatchProof, 16),
                $key
            );
            $this->sessionLogic->save($session);
            return gmp_strval($keyMatchProof, 16);
        } else {
            $this->sessionLogic->drop($srp6aAuthNIdentity->identityId, gmp_strval($publicEphemeralValueA, 16));
            return null;
        }
    }

    public function create(string $username, string $salt, string $passwordVerifier): ?int
    {
        $identity = $this->database->identity->fetch([$username], "username")[0] ?? null;
        if ($identity === null || $identity->id === null) {
            return null;
        }

        $srp6aAuthNIdentityRow = new Srp6aAuthNIdentityRow([
            "identityId" => $identity->id,
            "salt" => $salt,
            "passwordVerifier" => $passwordVerifier
        ]);

        $srp6aAuthNIdentityRow->id = $this->database->srp6aAuthNIdentity->insert($srp6aAuthNIdentityRow);
        return $srp6aAuthNIdentityRow->id === null ? null : $identity->id;
    }

    /**
     * Function to upgrade identity using username and password if the client can't use do it himself
     * @param non-empty-string $username
     * @param non-empty-string $password */
    public function upgrade(string $username, string $password): ?int
    {
        $salt = $this->srp6a->generateSalt();
        $privateKey = $this->srp6a->calcPrivateKey($salt, $username, $password);
        $passwordVerifier = $this->srp6a->calcPasswordVerifier($privateKey);
        return $this->create($username, gmp_strval($salt, 16), gmp_strval($passwordVerifier, 16));
    }

    /**
     * This function should ONLY be called if the client can't use loginChallenge & loginProof himself
     * @param non-empty-string $username
     * @param non-empty-string $password */
    public function fallback(string $username, string $password): ?int
    {
        $secretEphemeralValueA = $this->srp6a->generateSecretEphemeralValue();
        $publicEphemeralValueA = $this->srp6a->calcPublicEphemeralValueA($secretEphemeralValueA);
        $challenge = $this->authenticateChallenge($username, gmp_strval($publicEphemeralValueA, 16));
        if ($challenge !== null) {
            if ($challenge["expire"] < time()) {
                throw new \Exception("Challenge Expired.");
            }
            $publicEphemeralValueB = gmp_init($challenge["publicEphemeralValueB"], 16);
            $randomScramblingParameter = $this->srp6a->calcRandomScramblingParameter(
                $publicEphemeralValueA,
                $publicEphemeralValueB
            );
            $privateKey = $this->srp6a->calcPrivateKey(gmp_init($challenge["salt"], 16), $username, $password);
            $sessionKey = $this->srp6a->calcClientSessionKey(
                $publicEphemeralValueB,
                $privateKey,
                $secretEphemeralValueA,
                $randomScramblingParameter
            );
            $key = $this->srp6a->calcKey($sessionKey);
            $keyMatchProof = $this->srp6a->calcClientKeyMatch(
                $username,
                gmp_init($challenge["salt"], 16),
                $publicEphemeralValueA,
                $publicEphemeralValueB,
                $key
            );
            $serverKeyMatchProof = $this->authenticateProof(
                $username,
                gmp_strval($publicEphemeralValueA, 16),
                gmp_strval($keyMatchProof, 16)
            );
            $serverKeyMatchTest = $this->srp6a->calcServerKeyMatch($publicEphemeralValueA, $keyMatchProof, $key);
            if ($serverKeyMatchProof === gmp_strval($serverKeyMatchTest, 16)) {
                return $this->getSrp6aAuthNIdentity($username)?->identityId;
            }
        }
        return null;
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $publicEphemeralValueA */
    public function bumpSession(string $username, string $publicEphemeralValueA): ?int
    {
        $srp6aAuthNIdentity = $this->getSrp6aAuthNIdentity($username);
        if ($srp6aAuthNIdentity === null || $srp6aAuthNIdentity->identityId === null) {
            return null;
        }
        return $this->sessionLogic->bump($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $publicEphemeralValueA */
    public function loadSession(string $username, string $publicEphemeralValueA): ?Srp6aAuthNSessionRow
    {
        if (!$this->srp6a->validatePublicEphemeralValue(gmp_init($publicEphemeralValueA, 16))) {
            throw new \Exception("Invalid Public Ephemeral Value A.");
        }
        $srp6aAuthNIdentity = $this->getSrp6aAuthNIdentity($username);
        if ($srp6aAuthNIdentity === null || $srp6aAuthNIdentity->identityId === null) {
            return null;
        }
        return $this->sessionLogic->load($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
    }

    /**
     * @param non-empty-string $username
     * @param non-empty-string $publicEphemeralValueA */
    public function dropSession(string $username, string $publicEphemeralValueA): void
    {
        $srp6aAuthNIdentity = $this->getSrp6aAuthNIdentity($username);
        if ($srp6aAuthNIdentity === null || $srp6aAuthNIdentity->identityId === null) {
            return;
        }
        $this->sessionLogic->drop($srp6aAuthNIdentity->identityId, $publicEphemeralValueA);
    }
}
