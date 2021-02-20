package ch.zhaw.cailllev;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.mindrot.jbcrypt.*;

public class Utils {

    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
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

    private static boolean okWithR(BigInteger i, BigInteger r) {
        return !(i.mod(r)).equals((r.subtract(ONE)).divide(TWO));
    }

    protected static void safePrimeBM(int bitlength) {
        long start = System.currentTimeMillis();
        int bitlengthBMExp = 8;
        int bitlengthBM = 2 << bitlengthBMExp;  // 256

        safePrime(bitlengthBM);

        int diff = (int) ((System.currentTimeMillis() - start) / 1000);
        int estimate = diff * (2 << bitlength >> bitlengthBMExp) * 2;

        System.out.println("[*] Estimation to create " + 2 + " safe "
                + bitlength + " bit primes: ~ " + estimate + "s.");
    }


    public static BigInteger safePrime(int bitLength) {
        SecureRandom rnd = new SecureRandom();

        if (bitLength < 2) {
            throw new ArithmeticException("bitLength < 2");
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

                // now check q "exhaustivly"
            } while (!(q.isProbablePrime(CERTAINTY)));

            // here q is presumably a prime, now check if p is also a prime
            // p = 2q + 1
            p = q.multiply(TWO).add(ONE);

        } while (!(p.isProbablePrime(CERTAINTY)));

        return p;
    }

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

    protected static String createSalt(int rounds) {
        return BCrypt.gensalt(rounds);
    }

    protected static BigInteger[] get_num_from_password(String password, int lengthN, String salt) {

        String hashed = BCrypt.hashpw(password, salt);

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

    protected static byte[][] toBytesArray(byte[] bytes, int lengthN) {
        int blockSize = lengthN / 4;  // n == 128 -> 32 hex chars per block
        int blocks = (int) Math.ceil((double) bytes.length / blockSize)  * 2;

        byte[][] hexArray = new byte[blocks][blockSize];
        int i;
        for (i = 0; i < blocks - 1; i++) {
            hexArray[i] = Arrays.copyOfRange(bytes, i * blockSize, (i + 1) * blockSize);
        }
        // add last block (circumvent IndexOutOfBoundsException)
        hexArray[i] = Arrays.copyOfRange(bytes, i * blockSize, bytes.length);

        // padding
        int diff = blockSize - hexArray[i].length;
        byte[] withPadding = new byte[blockSize];
        for (int j = 0; j < blockSize; j++) {
            withPadding[j] = j < blockSize-diff ? hexArray[i][j] : 0;
        }
        hexArray[i] = withPadding;

        return hexArray;
    }
}
