package ch.zhaw.cailllev;

import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

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

    @org.junit.jupiter.api.Test
    void toChunks() {
        int lengthN = 11;
        int numBytes = (1 << lengthN) / 8;

        // test up to 4 blocks
        for (int blocks = 1; blocks <= 4; blocks++) {

            // test every count of bytes
            for (int i = 1; i <= numBytes; i++) {
                byte[] bytes = new byte[i + (blocks-1)*numBytes];

                Arrays.fill(bytes, (byte) 65);

                byte[][] chunks = Utils.toChunks(bytes, lengthN);

                // test num of blocks and length of last block
                assertEquals(blocks, chunks.length);
                assertEquals(numBytes, chunks[chunks.length - 1].length);

                // count padding bytes
                int countPadding = 0;
                int countAs = 0;
                for (Byte b : chunks[chunks.length - 1]) {
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
    void parseKeyfile() {
        int lengthN = 512;
        int hashRounds = 12;

        String keyfileName = "test_keyfile";
        String keyfileNameLong = keyfileName + Main.KEYFILE_EXTENSION;

        Main.initKeyfile(keyfileName, "a", lengthN, hashRounds);
        KeyfileContent kC = Utils.parseKeyfile(keyfileNameLong);

        assertEquals(kC.getLengthN(), lengthN);
        assertEquals(kC.getSalt().split("\\$")[2], "" + hashRounds);

        try {
            Files.deleteIfExists(Path.of(keyfileNameLong));
        } catch (IOException ex) {
            System.out.println("[!] Unable to delete keyfile " + keyfileNameLong + ", remove manually!");
        }
    }
}