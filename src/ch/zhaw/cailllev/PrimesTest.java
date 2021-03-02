package ch.zhaw.cailllev;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class PrimesTest {

    @Test
    void createTableOfPrimes() {
        int expectedPrimes = 10;
        int maxNumber = 30;
        int[] primes = Primes.createTableOfPrimes(maxNumber);

        assertEquals(expectedPrimes, primes.length);

        for (int i = 0; i < expectedPrimes - 1; i++) {
            assertTrue(primes[i] < primes[i+1]);
        }
    }

    @Test
    void safePrimeBM() {
        assertTrue(100 > Primes.safePrimeBM(10));
    }

    @Test
    void getThreadNumbers() {
        assertTrue(Primes.getThreadNumbers() >= 1);
    }

    @Test
    void getPrimes() {
        int[] bitLengths = new int[] {1024, 1024};

        BigInteger[] primes = Primes.getPrimes(bitLengths);

        for (BigInteger p : primes) {
            assertTrue(p.isProbablePrime(Primes.CERTAINTY));
        }
    }
}