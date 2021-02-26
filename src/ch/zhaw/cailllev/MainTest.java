package ch.zhaw.cailllev;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    private static final String keyfileName = "test_keyfile";
    private static final String keyfileNameOut = keyfileName + Main.KEYFILE_EXTENSION;

    private static final String fileToEncrypt = "to_encrypt.txt";
    private static final String fileToEncryptOut = "to_encrypt.txt" + Main.ENCRYPTED_EXTENSION;

    @org.junit.jupiter.api.Test
    void encryptAndDecrypt() throws IOException {
        // set up
        int lengthN = 2048;
        String password = "A";
        Main.initKeyfile(keyfileName, password, lengthN, 16);

        String content = "######################\nmy super test file\nmy super test file\n\n######################\n";

        Files.writeString(Path.of(fileToEncrypt), content);

        // encryption
        Main.encrypt(fileToEncrypt, keyfileNameOut);

        // delete plain file, so decrypt can save one
        Files.deleteIfExists(Path.of(fileToEncrypt));

        // decryption
        Main.decrypt(fileToEncryptOut, keyfileNameOut, true, true, password);

        // compare
        String actual = Files.readString(Path.of(fileToEncrypt));
        assertEquals(content, actual);

        // delete encrypted and keyfile
        Files.deleteIfExists(Path.of(fileToEncrypt));
        Files.deleteIfExists(Path.of(fileToEncryptOut));
        Files.deleteIfExists(Path.of(keyfileNameOut));
    }

    @org.junit.jupiter.api.Test
    void initAndParseKeyfile() throws IOException {
        int lengthN = 512;
        int hashRounds = 12;

        BigInteger[] ret = Main.initKeyfile(keyfileName, "a", lengthN, hashRounds);

        BigInteger n = ret[0];
        BigInteger e = ret[1];
        BigInteger d = ret[2];

        System.out.println(n.bitLength());
        assertTrue(n.bitLength() >= lengthN);

        // test encrypt and decrypt
        BigInteger m = BigInteger.TWO;
        BigInteger c = m.modPow(e, n);

        assertEquals(m, c.modPow(d, n));

        Files.deleteIfExists(Path.of(keyfileNameOut));
    }
}