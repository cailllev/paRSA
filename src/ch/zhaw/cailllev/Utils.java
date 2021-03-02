package ch.zhaw.cailllev;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.mindrot.jbcrypt.BCrypt;

class KeyfileContent {
    private final BigInteger n;
    private final int lengthN;
    private final BigInteger e;
    private final String salt;
    private final BigInteger quotient;
    private final BigInteger remainder;

    public KeyfileContent(BigInteger n, int lengthN, BigInteger e, String salt, BigInteger quotient,
                           BigInteger remainder) {
        this.n = n;
        this.lengthN = lengthN;
        this.e = e;
        this.salt = salt;
        this.quotient = quotient;
        this.remainder = remainder;
    }

    public BigInteger getN() {
        return n;
    }

    public int getLengthN() {
        return lengthN;
    }

    public BigInteger getE() {
        return e;
    }

    public String getSalt() {
        return salt;
    }

    public BigInteger getQuotient() {
        return quotient;
    }

    public BigInteger getRemainder() {
        return remainder;
    }
}

public class Utils {
    /**
     * Check if the password is at least 10 chars long, contains at least one number, at least one lowercase letter, at
     * least one uppercase letter and at least one special char.
     * @param password  the password to check
     * @return          true if all checks succeed
     */
    protected static boolean checkPasswordStrength(String password) {
        if (password.length() < 10) {
            System.out.println("[!] Password has to be at least 10 characters long.");
            return false;
        }

        if (!password.matches(".*[0-9].*")) {
            System.out.println("[!] Password has to contain at least one number.");
            return false;
        }

        if (!password.matches(".*[A-Z].*")) {
            System.out.println("[!] Password has to contain at least one uppercase character.");
            return false;
        }

        if (!password.matches(".*[a-z].*")) {
            System.out.println("[!] Password has to contain at least one lowercase character.");
            return false;
        }

        if (!password.matches(".*[!@#$%&*()_+=|<>?{}\\[\\]~-].*")) {
            System.out.println("[!] Password has to contain at least one special character.");
            return false;
        }

        return true;
    }

    /**
     * Hashes a string with BCrypt, then converts that hash to a BigInteger. If that BigInteger is bigger than n,
     * right shift it until it fits.
     * @param password  the password to hash
     * @param lengthN   the size of n
     * @param salt      the salt to use for the hashing
     * @return  the hashed string as a BigInteger plus it's difference in bits to n
     */
    protected static BigInteger getNumFromPassword(String password, int lengthN, String salt) {

        String[] s = null;
        try {
            s = BCrypt.hashpw(password, salt).split("\\$");
        }

        catch (Exception ex) {
            System.out.println("[!] Internal BCrypt error. Exiting...");
            System.exit(1);
        }

        String rounds = s[2];
        String hash = s[3];

        BigInteger dIn = new BigInteger(1, hash.getBytes());
        int bitDiff = lengthN - dIn.bitLength();

        // if dIn is bigger than n -> rightshift so it fits
        if (bitDiff < 0) {
            dIn = dIn.shiftRight(-bitDiff + 1);
        }

        //only print this if not testing exhaustively (i.e.rounds != 16)
        if (rounds.equals("16"))
            System.out.println("[*] Password hashed and transformed to number < n");

        return dIn;
    }

    protected static byte[][] toChunks(byte[] bytes, int lengthN) {
        int blockSize = lengthN / 8;  // n == 2048 -> 256 bytes per block
        int blocks = (int) Math.ceil((double) bytes.length / blockSize);

        byte[][] hexArray = new byte[blocks][blockSize];
        for (int i = 0; i < blocks - 1; i++) {
            hexArray[i] = Arrays.copyOfRange(bytes, i * blockSize, (i + 1) * blockSize);
        }

        // add last block with padding
        int start = (blocks-1)*blockSize;
        if (bytes.length - start >= 0)
            System.arraycopy(bytes, start, hexArray[blocks - 1], 0, bytes.length - start);

        return hexArray;
    }

    protected static KeyfileContent parseKeyfile(String keyfileName) {

        try (BufferedReader br = new BufferedReader(new FileReader(keyfileName))) {
            // read header
            br.readLine();

            // read n
            String[] ns = br.readLine().split(":");
            BigInteger n = new BigInteger(ns[0]);
            int lengthN = Integer.parseInt(ns[1]);

            // read e
            BigInteger e = new BigInteger(br.readLine());

            // read d
            String[] ds = br.readLine().split(":");
            String salt = ds[0];
            BigInteger quotient = new BigInteger(ds[1]);
            BigInteger remainder = new BigInteger(ds[2]);

            return new KeyfileContent(n, lengthN, e, salt, quotient, remainder);

        } catch (FileNotFoundException ex) {
            System.out.println("[!] Keyfile " + keyfileName + " not found. Exiting...");
            System.exit(1);

        } catch (IOException ex) {
            System.out.println("[!] IOException when reading keyfile " + keyfileName + ". Exiting...");
            System.exit(1);
        }

        catch (Exception ex) {
            System.out.println("[!] Error parsing keyfile " + keyfileName + ". Exiting...");
            System.exit(1);
        }

        return null;
    }
}
