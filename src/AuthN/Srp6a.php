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

use GMP;

/**
 * Secure Remote Password Authentication Functions
 * SRP6a is a secure password-based authentication and key-exchange protocol.
 */
class Srp6a
{
    private const SALT_BYTES = 8;
    private const RAND_BYTES = 32;
    private const HASH_ALGO  = "sha512";
    private GMP $safePrime; //N
    private GMP $generatorModulo; //g

    /**
     * Calculates g^exponent % N
     */
    private function calcGeneratorModuloPowM(GMP $exponent): GMP
    {
        $g = $this->generatorModulo;
        $N = $this->safePrime;
        return gmp_powm($g, $exponent, $N);
    }

    /**
     * Hash function (H)
     */
    private function hash(string $data): GMP
    {
        return gmp_init(hash(self::HASH_ALGO, $data), 16);
    }

    /**
     * Calculates the Multiplier Parameter (k) = H(N,g)
     */
    private function calcMultiplierParameter(): GMP
    {
        $N = gmp_strval($this->safePrime, 16);
        $g = gmp_strval($this->generatorModulo, 16);
        return $this->hash($N . $g);
    }

    /**
     * @param string $safePrime       is a large safe prime (N = 2q+1, where q is prime)
     * @param string $generatorModulo is the generator modulo for the safePrime
     * @note  Both $safePrime and $generatorModulo=2 can be generated using:
     * echo "0x$(openssl dhparam -2 -text 1024 2>/dev/null | grep prime -A 9 | grep -v prime | sed -e "s/ \|://g" | tr -d '\n')"
     */
    public function __construct(
        string $safePrime,
        string $generatorModulo,
    ) {
        $this->safePrime = gmp_init($safePrime);
        $this->generatorModulo = gmp_init($generatorModulo);
        if (gmp_prob_prime($this->safePrime) === 0) {
            throw new \Exception("$this->safePrime is not prime");
        }
        if (gmp_prob_prime(($this->safePrime - 1) / 2) === 0) {
            throw new \Exception("($this->safePrime-1)/2 is not prime");
        }
    }

    /**
     * Generates cryptographically secure pseudo-random salt value (s)
     */
    public function generateSalt(): GMP
    {
        return gmp_init(bin2hex(random_bytes(self::SALT_BYTES)), 16);
    }

    /**
     * Calculates the client's private key (x)
     * x = hash(salt || hash(username || ":" || password))
     */
    public function calcPrivateKey(GMP $salt, string $username, string $password): GMP
    {
        // The hex salt string has an even number of characters
        $s = gmp_strval($salt, 16);
        if (strlen($s) % 2 !== 0) {
            $s = "0" . $s;
        }
        $x = $this->hash($s . $this->hash($username . ":" . $password));
        $N = $this->safePrime;
        if ($x < $N) {
            return $x;
        } else {
            return $x % ($N - 1);
        }
    }

    /**
     * Calculates the client's password verifier (v)
     * v = v = g^x
     */
    public function calcPasswordVerifier(GMP $privateKey): GMP
    {
        return $this->calcGeneratorModuloPowM($privateKey);
    }

    /**
     * Generates cryptographically secure pseudo-random Secret Ephemeral Value (a or b)
     */
    public function generateSecretEphemeralValue(): GMP
    {
        return gmp_init(bin2hex(random_bytes(self::RAND_BYTES)), 16);
    }

    /**
     * Calculates the client's Public Ephemeral Value (A)
     * A = g^a
     */
    public function calcPublicEphemeralValueA(GMP $secretEphemeralValueA): GMP
    {
        return $this->calcGeneratorModuloPowM($secretEphemeralValueA);
    }

    /**
     * Calculates the server's Public Ephemeral Value (B)
     * B = kv + g^b
     */
    public function calcPublicEphemeralValueB(GMP $passwordVerifier, GMP $secretEphemeralValueB): GMP
    {
        $k = $this->calcMultiplierParameter();
        $v = $passwordVerifier;
        $b = $secretEphemeralValueB;
        return ($k * $v + $this->calcGeneratorModuloPowM($b)) % $this->safePrime;
    }

    /**
     * tests if a Public Ephemeral Value module N is not zero.
     */
    public function validatePublicEphemeralValue(GMP $publicEphemeralValue): bool
    {
        return($publicEphemeralValue % $this->safePrime != 0);
    }

    /**
     * Calculates the Random Scrambling Parameter (u)
     * u = Hash(A, B)
     */
    public function calcRandomScramblingParameter(GMP $publicEphemeralValueA, GMP $publicEphemeralValueB): GMP
    {
        $A = gmp_strval($publicEphemeralValueA, 16);
        $B = gmp_strval($publicEphemeralValueB, 16);
        return $this->hash($A . $B);
    }

    /**
     * Calculates the client's session key (S)
     * S = (B - kg^x) ^ (a + ux)
     */
    public function calcClientSessionKey(
        GMP $publicEphemeralValueB,
        GMP $privateKey,
        GMP $secretEphemeralValueA,
        GMP $randomScramblingParameter
    ): GMP {
        $B = $publicEphemeralValueB;
        $k = $this->calcMultiplierParameter();
        $x = $privateKey;
        $a = $secretEphemeralValueA;
        $u = $randomScramblingParameter;
        return gmp_powm($B - $k * $this->calcGeneratorModuloPowM($x), $a + $u * $x, $this->safePrime);
    }

    /**
     * Calculates the server session key (S)
     * S = (Av^u) ^ b
     */
    public function calcServerSessionKey(
        GMP $publicEphemeralValueA,
        GMP $passwordVerifier,
        GMP $randomScramblingParameter,
        GMP $secretEphemeralValueB
    ): GMP {
        $A = $publicEphemeralValueA;
        $v = $passwordVerifier;
        $u = $randomScramblingParameter;
        $N = $this->safePrime;
        $b = $secretEphemeralValueB;
        return gmp_powm($A * gmp_powm($v, $u, $N), $b, $N);
    }

    /**
     * Calculates a key from a session key (K)
     * K = H(S)
     */
    public function calcKey(GMP $sessionKey): GMP
    {
        return $this->hash(gmp_strval($sessionKey, 16));
    }

    /**
     * Calculates the server's key proof (M)
     * M = H(A, M, K)
     */
    public function calcServerKeyMatch(GMP $publicEphemeralValueA, GMP $clientKeyMatchProof, GMP $key): GMP
    {
        $A = gmp_strval($publicEphemeralValueA, 16);
        $M = gmp_strval($clientKeyMatchProof, 16);
        $K = gmp_strval($key, 16);
        return $this->hash($A . $M . $K);
    }

    /**
     * Calculates the client's key proof (M)
     * M = H(H(N) xor H(g), H(I), s, A, B, K)
     */
    public function calcClientKeyMatch(
        string $username,
        GMP $salt,
        GMP $publicEphemeralValueA,
        GMP $publicEphemeralValueB,
        GMP $key
    ): GMP {
        $HashN = $this->hash(gmp_strval($this->safePrime, 16));
        $HashG = $this->hash(gmp_strval($this->generatorModulo, 16));
        return $this->hash(
            gmp_strval($HashN ^ $HashG, 16) .
            gmp_strval($this->hash($username), 16) .
            gmp_strval($salt, 16) .
            gmp_strval($publicEphemeralValueA, 16) .
            gmp_strval($publicEphemeralValueB, 16) .
            gmp_strval($key, 16)
        );
    }
}
