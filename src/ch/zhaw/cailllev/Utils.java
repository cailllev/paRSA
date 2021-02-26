package ch.zhaw.cailllev;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

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

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger SIX = BigInteger.valueOf(6);

    // log2(10^20) == 66.5;
    private static final int CERTAINTY = 67;

    /**
     * Creates an array of primes up to {@code max}.
     * @param max   upper bound of primes
     * @return      the array of primes
     */
    public static int[] createTableOfPrimes(int max) {
        ArrayList<Integer> primes = new ArrayList<>();
        for (int i = 2; i <= max; i++){
            if ((new BigInteger(String.valueOf(i))).isProbablePrime(CERTAINTY)){
                primes.add(i);
            }
        }

        return primes.stream().mapToInt(i1 -> i1).toArray();
    }

    /**
     * @return i % 6 == 5
     */
    private static boolean okWith5Mod6(BigInteger i) {
        return (i.mod(SIX)).equals(FIVE);
    }

    /**
     * @return i % r == (r-1)/2
     */
    private static boolean okWithR(BigInteger i, BigInteger r) {
        return !(i.mod(r)).equals((r.subtract(ONE)).divide(TWO));
    }

    /**
     * Prints the estimate of how long the prime generation takes for 2 primes with bit length {@code bitLength}.
     * @param bitLength the bit length of the primes to generate
     */
    protected static void safePrimeBM(int bitLength) {
        long start = System.currentTimeMillis();
        int bitLengthBMExp = 8;
        int bitLengthBM = 2 << bitLengthBMExp;  // 256

        safePrime(bitLengthBM);

        double diff = (System.currentTimeMillis() - start) / (double) 1000;
        int estimate = (int) (diff * ((double) bitLength / bitLengthBMExp) * 2);

        System.out.println("[*] Estimation to create " + 2 + " safe "
                + bitLength + " bit primes: ~ " + estimate + "s.");
    }

    /**
     * Creates a safe prime number p with bit length {@code bitLength}. Safe means that (p-1)/2 is also a prime number.
     * Finally, p is with certainty of 2^67 a prime number.
     * @param bitLength the bit length of prime p
     * @return          prime p
     */
    protected static BigInteger safePrime(int bitLength) {
        SecureRandom rnd = new SecureRandom();

        if (bitLength < 16) {
            System.out.println("[!] Bit length cannot be smaller than 16 when creating a safe prime.");
            System.exit(1);
        }

        int[] tableOfPrimes = createTableOfPrimes(1024);

        BigInteger r, q, p;

        do {

            do {

                // do fast tests "q.mod(6) != 5" and "q.mod(r) != (r-1)/2"
                while (true) {

                    // check 5 mod 6
                    do {
                        q = new BigInteger(bitLength, rnd);
                    } while (q.bitLength() < bitLength && !(okWith5Mod6(q)));

                    // check with r
                    boolean foundProblem = false;
                    for (int i = 1; i < tableOfPrimes.length; i++) {
                        r = BigInteger.valueOf(tableOfPrimes[i]); //starts at val 3
                        if (!(okWithR(q, r))) {
                            foundProblem = true;
                            break;
                        }
                    }

                    if (!foundProblem)
                        break;
                }

                // now check q "exhaustively"
            } while (!(q.isProbablePrime(CERTAINTY)));

            // here q is presumably a prime, now check if p is also a prime
            // p = 2q + 1
            p = q.multiply(TWO).add(ONE);

        } while (!(p.isProbablePrime(CERTAINTY)));

        return p;
    }

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
            System.out.println("[!] Internal BCrypt error.");
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
            System.out.println("[!] Keyfile " + keyfileName + " not found.");
            System.exit(1);

        } catch (IOException ex) {
            System.out.println("[!] IOException when reading keyfile " + keyfileName + ".");
            System.exit(1);
        }

        catch (Exception ex) {
            System.out.println("[!] Error parsing keyfile " + keyfileName + ".");
            System.exit(1);
        }

        return null;
    }
}
