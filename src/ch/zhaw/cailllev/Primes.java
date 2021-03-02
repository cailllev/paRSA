package ch.zhaw.cailllev;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Primes {
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger SIX = BigInteger.valueOf(6);

    // log2(10^20) == 66.5;
    protected static final int CERTAINTY = 67;

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
    protected static int safePrimeBM(int bitLength) {
        long start = System.currentTimeMillis();
        int bitLengthBMExp = 8;
        int bitLengthBM = 2 << bitLengthBMExp;  // 256

        safePrime(bitLengthBM);

        double diff = (System.currentTimeMillis() - start) / 1000.0;
        int estimate = (int) (diff * ((double) bitLength / bitLengthBMExp));

        System.out.println("[*] Estimation to create safe primes for "
                + bitLength + " bit RSA modulus: ~ " + estimate + "s.");
        return estimate;
    }

    /**
     * Creates a safe prime number p with bit length {@code bitLength}. Safe means that (p-1)/2 is also a prime number.
     * Finally, p is with certainty of 2^67 a prime number.
     * @param bitLength the bit length of prime p
     * @return          prime p
     */
    private static BigInteger safePrime(int bitLength) {
        SecureRandom rnd = new SecureRandom();

        if (bitLength < 16) {
            System.out.println("[!] Bit length cannot be smaller than 16 when creating a safe prime. Exiting...");
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
     * https://stackoverflow.com/questions/1980832/how-to-scale-threads-according-to-cpu-cores#1980858
     * @return "optimal" number of threads
     */
    protected static int getThreadNumbers() {
        return Runtime.getRuntime().availableProcessors();
    }

    /**
     * https://www.baeldung.com/java-executor-service-tutorial
     * creates primes with bitLengths b for b in bitLengths
     *
     * @param bitLengths the lengths of the primes to be created
     * @return safe prime numbers
     */
    protected static BigInteger[] getPrimes(int[] bitLengths) {
        int threadsCount = getThreadNumbers();
        int primesCount = bitLengths.length;
        BigInteger[] primes = new BigInteger[bitLengths.length];

        ExecutorService executor = Executors.newFixedThreadPool(threadsCount);

        // do one safePrime() per bitLengths
        for (int c = 0; c < primesCount; c++) {

            int bitLength = bitLengths[c];
            Callable<BigInteger> callableTask = () -> safePrime(bitLength);

            List<Callable<BigInteger>> callableTasks = new ArrayList<>();
            for (int i = 0; i < threadsCount; i++) {
                callableTasks.add(callableTask);
            }


            System.out.println("[*] Finding a safe prime with " + threadsCount + " threads..." );
            try {
                primes[c] = executor.invokeAny(callableTasks);
            } catch (InterruptedException ex) {
                System.out.println("[!] Thread was interrupted when creating a safe prime. Exiting...");
                System.exit(1);
            } catch (ExecutionException ex) {
                System.out.println("[!] Thread encountered an exception during execution. Exiting...");
                System.exit(1);
            }
        }

        executor.shutdown();
        return primes;
    }
}
