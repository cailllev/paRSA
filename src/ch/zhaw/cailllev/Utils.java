package ch.zhaw.cailllev;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import org.mindrot.jbcrypt.BCrypt;

public class Utils {

    // private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    // private static final BigInteger THREE = BigInteger.valueOf(3);
    // private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger SIX = BigInteger.valueOf(6);

    // log2(10^20) == 66.5;
    private static final int CERTAINTY = 67;


    public static int[] createTableOfPrimes(int max) {
        ArrayList<Integer> primes = new ArrayList<>();
        for (int i = 2; i <= max; i++){
            if ((new BigInteger(String.valueOf(i))).isProbablePrime(CERTAINTY)){
                primes.add(i);
            }
        }

        return primes.stream().mapToInt(i1 -> i1).toArray();
    }

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
     * Prints the estimate of how long the prime generation takes for 2 primes with bit length {@code bitLength}
     * @param bitLength the bit length of the primes to generate
     */
    protected static void safePrimeBM(int bitLength) {
        long start = System.currentTimeMillis();
        int bitLengthBMExp = 8;
        int bitLengthBM = 2 << bitLengthBMExp;  // 256

        safePrime(bitLengthBM);

        int diff = (int) ((System.currentTimeMillis() - start) / 1000);
        int estimate = diff * (2 << bitLength >> bitLengthBMExp) * 2;

        System.out.println("[*] Estimation to create " + 2 + " safe "
                + bitLength + " bit primes: ~ " + estimate + "s.");
    }

    /**
     * creates a safe prime number p with bit length {@code bitLength}
     * safe means that (p-1)/2 is also a prime number
     * p is with certainty 2^67 a prime number
     * @param bitLength the bit length of prime p
     * @return prime p
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
                        q = new BigInteger(bitLength - 1, rnd);
                    } while (!(okWith5Mod6(q)));

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
     * check if the password is at least 10 chars long, contains at least one number, at least one lowercase letter, at
     * least one uppercase letter and at least one special char
     * @param password the password to check
     * @return true if all checks succeed
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

    protected static BigInteger[] getNumFromPassword(String password, int lengthN, String salt) {

        String hashed = null;
        try {
            hashed = BCrypt.hashpw(password, salt);
        }

        catch (Exception ex) {
            System.out.println("[!] Internal BCrypt error.");
            System.exit(1);
        }

        String[] s = hashed.split("\\$");
        String rounds = s[2];
        String hash = s[3];

        BigInteger dIn = new BigInteger(1, hash.getBytes());
        int bit_diff = lengthN - dIn.bitLength();

        // if d_in is bigger than n -> rightshift so it fits
        if (bit_diff < 0) {
            dIn = dIn.shiftRight(-bit_diff);
            bit_diff = 0;
        }

        // still bigger than n -> shift once more
        if (dIn.shiftRight(lengthN).compareTo(BigInteger.ZERO) >= 0) {
            dIn = dIn.shiftRight(1);
        }

        //only print this if not testing exhaustively(i.e.rounds == 16)
        if (rounds.equals("16"))
            System.out.println("[*] Password hashed and transformed to number < n");

        return new BigInteger[]{dIn, BigInteger.valueOf(bit_diff)};
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
}
