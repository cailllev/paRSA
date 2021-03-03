package ch.zhaw.cailllev;

import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    private static final String keyfileName = "test_keyfile";
    private static final String keyfileNameOut = keyfileName + Main.KEYFILE_EXTENSION;

    @org.junit.jupiter.api.Test
    void checkPasswordStrength() {
        assertFalse(Utils.checkPasswordStrength("012345aA!"));   // fails length
        assertTrue(Utils.checkPasswordStrength("012345aA!9"));  // okay

        assertFalse(Utils.checkPasswordStrength("Aaaaaaaaa!"));  // fails at least one number
        assertTrue(Utils.checkPasswordStrength("Aaaaaaaaa!1"));  // okay

        assertFalse(Utils.checkPasswordStrength("aaaaaaaa1!"));  // fails uppercase character
        assertTrue(Utils.checkPasswordStrength("Aaaaaaaa1!"));  // okay

        assertFalse(Utils.checkPasswordStrength("AAAAAAAA1!"));  // fails lowercase character
        assertTrue(Utils.checkPasswordStrength("aAAAAAAA1!"));   // okay

        assertFalse(Utils.checkPasswordStrength("AAAAAAAA1a"));  // fails special character
        assertTrue(Utils.checkPasswordStrength("aAAAAAAA1!"));   // okay
    }

    @org.junit.jupiter.api.Test
    void getNumFromPassword() {
        String password = "A";
        String salt = BCrypt.gensalt(4);

        // test from 2^1 to 2^12, i.e. 2 to 4096 bits
        for (int lengthN = 1; lengthN <= 13; lengthN++) {
            BigInteger n = BigInteger.valueOf(1 << lengthN);

            // test exhausively that num < n
            for (int i = 0; i < 100; i++) {
                BigInteger num = Utils.getNumFromPassword(password, lengthN, salt);
                assertTrue(num.compareTo(n) < 0);
            }
        }
    }

    @Test
    void getThreadNumbers() {
        assertTrue(Utils.getThreadNumbers() >= 1);
    }

    @Test
    void splitElemsToThreads() {
        int elems, threads;
        int[] ret, expected;

        elems = 5;
        threads = 3;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {2, 2, 1};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }

        elems = 6;
        threads = 4;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {2, 2, 2};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }

        elems = 7;
        threads = 3;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {3, 2, 2};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }

        elems = 7;
        threads = 4;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {2, 2, 2, 1};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }

        elems = 9;
        threads = 4;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {3, 3, 3};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }

        elems = 10;
        threads = 4;
        ret = Utils.splitElemsToThreads(threads, elems);
        expected = new int[] {3, 3, 2, 2};
        for (int i = 0; i < ret.length; i++) {
            assertEquals(ret[i], expected[i]);
        }
    }

    @org.junit.jupiter.api.Test
    void toChunks() {
        int lengthN = 2048;
        int numBytes = lengthN / 8;
        int threadCount = Utils.getThreadNumbers();

        // test up to 12 chunks
        for (int chunks = 1; chunks <= 12; chunks++) {

            // test every count of bytes
            for (int i = 1; i <= numBytes; i++) {
                byte[] bytes = new byte[i + (chunks-1)*numBytes * threadCount];

                Arrays.fill(bytes, (byte) 65);

                byte[][][] chunked = Utils.toChunks(bytes, lengthN, threadCount);

                int actualThreads = chunked.length;
                int lastThreadLastChunk = chunked[actualThreads - 1].length - 1;

                // test threads
                assertTrue(threadCount >= actualThreads);

                // count padding bytes and length of last block
                int countPadding = 0;
                int countAs = 0;
                for (Byte b : chunked[actualThreads - 1][lastThreadLastChunk]) {
                    if (b == 0)
                        countPadding++;
                    else
                        countAs++;
                }

                // test padding
                assertEquals(numBytes, countPadding + countAs);
                assertEquals(numBytes - i, countPadding);
            }
        }
    }

    @org.junit.jupiter.api.Test
    void parseKeyfile() throws IOException {
        int lengthN = 512;
        int hashRounds = 12;

        Main.initKeyfile(keyfileName, "a", lengthN, hashRounds);
        KeyfileContent kC = Utils.parseKeyfile(keyfileNameOut);

        assertEquals(kC.getLengthN(), lengthN);
        assertEquals(kC.getSalt().split("\\$")[2], "" + hashRounds);

        Files.deleteIfExists(Path.of(keyfileNameOut));
    }
}