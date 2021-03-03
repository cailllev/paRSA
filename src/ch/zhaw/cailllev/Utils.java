package ch.zhaw.cailllev;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
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

    /**
     * https://stackoverflow.com/questions/1980832/how-to-scale-threads-according-to-cpu-cores#1980858
     * @return "optimal" number of threads
     */
    protected static int getThreadNumbers() {
        return Runtime.getRuntime().availableProcessors();
    }

    /**
     * Splits up a one dimensional array into a 3 dimensional array. The first dimension is for the threads, the 2nd so
     * that the bytes < n, and the last is for the individual bytes.
     * @param bytes         the one dimensional array input
     * @param lengthN       the bitLength of n
     * @param threadCount   how many threads are available for processing
     * @return  array[threads][blocksize][blocks]
     */
    protected static byte[][][] toChunks(byte[] bytes, int lengthN, int threadCount) {
        // n == 2048 -> 256 bytes chunkSize
        int chunkSize = (int) Math.ceil((double) lengthN / 8);

        // 256 bytes chunkSize & 1000 input bytes -> 1000 / 256 = 4
        int chunks = (int) Math.ceil((double) bytes.length / chunkSize);

        byte[][] chunkedArray = new byte[chunks][chunkSize];
        for (int i = 0; i < chunks - 1; i++) {
            chunkedArray[i] = Arrays.copyOfRange(bytes, i * chunkSize, (i + 1) * chunkSize);
        }

        // add last block with padding
        int start = (chunks-1)*chunkSize;
        if (bytes.length - start >= 0)
            System.arraycopy(bytes, start, chunkedArray[chunks -1], 0, bytes.length - start);

        // now split those arrays up for the threads
        int[] chunksPerThread = splitElemsToThreads(threadCount, chunks);
        threadCount = chunksPerThread.length;

        byte[][][] threadChunkedArray = new byte[threadCount][][];
        int chunksAllocated = 0;
        for (int i = 0; i < threadCount; i++) {
            int chunksToAdd = chunksPerThread[i];
            threadChunkedArray[i] = Arrays.copyOfRange(chunkedArray, chunksAllocated, chunksAllocated + chunksToAdd);
            chunksAllocated += chunksToAdd;
        }

        return threadChunkedArray;
    }

    protected static int[] splitElemsToThreads(int threadCount, int elemsCount) {
        int[] elemsPerThread;

        if (threadCount >= elemsCount) {
            threadCount = elemsCount;

            elemsPerThread = new int[threadCount];
            Arrays.fill(elemsPerThread, 1);

        } else {
            // 6 elems, 4 threads -> t1 has 2 elems, t2 has 2 elems, t3 has 2 elems, t4 unused! -> 2 elems max
            // 5 elems, 3 threads -> t1 has 2 elems, t2 has 2 elems, t3 has 1 chunk -> 2 elems max
            // 7 elems, 3 threads -> t1 has 3 elems, t2 has 2 elems, t3 has 2 elems -> 3 elems max
            int maxElemsPerThread = (int) Math.ceil((double) elemsCount / threadCount);

            // ceil(6 / 2) = 3 --> 3 < 4  -> only 3 threads needed
            // ceil(5 / 2) = 3 --> 3 !< 3 -> all 3 threads needed
            // ceil(7 / 3) = 3 --> 3 !< 3 -> all 3 threads needed
            if ((int) Math.ceil((double) elemsCount / maxElemsPerThread) < threadCount) {
                threadCount = (int) Math.ceil((double) elemsCount / maxElemsPerThread);
            }

            // now split chunks to threads
            elemsPerThread = new int[threadCount];
            Arrays.fill(elemsPerThread, maxElemsPerThread);

            // calc the chunks in the last thread
            int chunksInLastThread =  elemsCount - (threadCount-1) * maxElemsPerThread;
            elemsPerThread[threadCount -1] = chunksInLastThread;

            // split the chunks equally
            for (int i = threadCount - 2; i >= 0; i--) {
                // check if other threads have more than one chunk more, i.e. 3,3,1 -> 3,2,2
                if (elemsPerThread[i] > elemsPerThread[threadCount -1] + 1) {
                    elemsPerThread[i]--;
                    elemsPerThread[threadCount -1]++;
                }
            }
        }

        return elemsPerThread;
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
