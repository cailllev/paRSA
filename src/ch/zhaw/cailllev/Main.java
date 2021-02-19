package ch.zhaw.cailllev;

import static ch.zhaw.cailllev.Utils.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {

    private static final String ENCRIPTED_EXTENSION = ".parsa";
    private static final String KEYFILE_EXTENSION = ".pub";

    private static final String HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE - PARSA ========\n";
    private static final String TAIL_KEYFILE = "========= END PUBLIC KEYFILE - PARSA =========\n";

    private static final int HASH_ROUNDS = 16; //2^16
    private static final int LENGTH_N = 2048;

    public static BigInteger[] initKeyfile(String name, String password, int lengthN, int hashRounds) throws Exception {
        System.out.println("[*] Create keyfile with " + lengthN + " bits and " + hashRounds + " hash rounds.");

        String keyfileOutName = name + KEYFILE_EXTENSION;

        File keyfile = new File(keyfileOutName);
        if (keyfile.exists())
            throw new Exception("Keyfile " + keyfileOutName + " already exists.");



        // test if in debug / testing mode
        boolean debug;
        if (password != null) {
            debug = false;
            lengthN = 2048;
            hashRounds = 16;

        } else {
            debug = true;
        }

        if (debug && lengthN < 32) {
            throw new Exception("[!] Length of n has to be at least 32 bit, functionality wise.");
        }
        else if (lengthN < 2048) {
            throw new Exception("[!] Length of n has to be at least 2048 bit, security wise.");
        }

        //   100000000 // number
        // & 011111111 // number - 1
        // -----------
        //   000000000
        if ((lengthN & (lengthN - 1)) != 0)
            throw new Exception("[!] Length of n must be power of 2 (2048, 4096, ...).");

        SecureRandom secRandom = new SecureRandom();
        int delta = 5 + secRandom.nextInt(10);
        int lengthP = lengthN / 2 + delta;
        int lengthQ = lengthN - lengthP - 1;

        safePrimeBM(lengthN / 2);
        BigInteger p = safePrime(lengthP);
        BigInteger q = safePrime(lengthQ);

        BigInteger n = p.multiply(q);
        BigInteger ONE = BigInteger.ONE;
        BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE));

        if (!debug) {
            while (true) {
                System.out.println("[*] Please enter the password to use for the encription: ");
                password = new String(System.console().readPassword());

                if (!checkPasswordStrength(password)) {
                    continue;
                }

                System.out.println("[*] Please re-enter the password: ");
                String passwordCheck = new String(System.console().readPassword());

                if (passwordCheck.equals(password)) {
                    break;
                }
                else {
                    System.out.println("[!] Passwords did not match, please try again.");
                }
            }
        }

        String salt = createSalt(hashRounds);
        BigInteger[] hashed  = get_num_from_password(password, lengthN, salt);
        BigInteger dIn = hashed[0];
        int bitDiff = hashed[1].intValue();

        BigInteger e, d, diff;

        SecureRandom random = new SecureRandom();
        while (true) {

            // create d near at phi, regardless where d_in is
            // 0 ... d_in ..................... d ........ phi
            // 0 .............................. d . d_in . phi
            int offsetBitsize = 16;
            int randomOffset = random.nextInt(1 << (offsetBitsize - 1));

            d = dIn.shiftLeft(bitDiff - offsetBitsize).add(BigInteger.valueOf(randomOffset));

            if (d.gcd(phi).equals(BigInteger.ONE)) {
                e = d.modInverse(phi);
                diff = d.subtract(dIn);

                // enforce big e 's (at least as big as d)
                if (e.bitLength() > (lengthN - offsetBitsize)) {
                    System.out.println("[*] Found valid d and e");
                    break;
                }
            }
        }

        BigInteger quotient = diff.divide(dIn);
        BigInteger remainder = diff.mod(dIn);

        BufferedWriter writer = new BufferedWriter(new FileWriter(keyfileOutName));
        writer.write(HEADER_KEYFILE);
        writer.write(n.toString() + ":" + lengthN + "\n");
        writer.write(e.toString() + "\n");
        writer.write(salt + ":" + quotient.toString() + ":" + remainder.toString() + "\n");
        writer.write(TAIL_KEYFILE);
        writer.close();

        // i.e. in Test / Debug mode
        if (debug) {
            System.out.println("[#] n:    " + n);
            System.out.println("[#] e:    " + e);
            System.out.println("[#] d:    " + d);
            System.out.println("[#] dIn:  " + dIn);
            System.out.println("[#] diff: " + diff);

            return new BigInteger[]{n, e, d, dIn};
        }

        return null;
    }

    public static void encript(String filename, String keyfileName) {

    }

    public static void decript(String filename, String keyfileName, String password, boolean verbose, boolean safe) {

    }

    /**
     * normal rsa:
     * 1. choose e
     * 2. d is e's mod_inv in phi
     * public = (n,e)
     * private = (n,d)
     *
     *
     * "password" rsa:
     * 1. enter password -> d
     * 2. d_prime = next_prime(d + random)
     * 3. diff = d_prime - d
     * 4. e is d's mod_inv in phi, if no inv -> go to 2.
     * public = (n,e,diff)
     * private = (n,password)
     *
     * @param args the arguments for the program
     */
    public static void main(String[] args) throws Exception {
        parse(args);
    }

    public static void parse(String[] args) throws Exception {
        if (args.length == 0) {
            printHelp();
            return;
        }

        switch (args[0]) {
            case "-h", "--help" -> printHelp();
            case "-i", "--init" -> {
                String keyfileName = args[1];
                System.out.println("[*] Init keyfile: " + keyfileName);
                initKeyfile(keyfileName, null, LENGTH_N, HASH_ROUNDS);
            }
            case "-k", "--keyfile" -> {
                String keyfile_name = args[1];

                if (args[2].equals("-e") || args[2].equals("--encript")) {
                    String file = args[3];
                    System.out.println("[*] Encript: " + file);

                    encript(file, keyfile_name);
                } else if (args[2].equals("-f") || args[2].equals("--decript")) {
                    String file = args[3];
                    System.out.println("[*] Decript: " + file);

                    boolean verbose = args[4].equals("-v") || args[4].equals("--verbose")
                            || args[5].equals("-v") || args[5].equals("--verbose");

                    boolean save = args[4].equals("-s") || args[4].equals("--save")
                            || args[5].equals("-s") || args[5].equals("--save");

                    decript(file, keyfile_name, "", verbose, save);
                } else {
                    System.out.println("**************************************************************************");
                    System.out.println("If a keyfile is supplied, the encription or decription flag has to be set!");
                    System.out.println("**************************************************************************\n");
                    printHelp();
                }
            }
            default -> {
                System.out.println("************************************************************");
                System.out.println("Either the init flag or the keyfile flag has to be supplied!");
                System.out.println("************************************************************\n");
                printHelp();
            }
        }
    }

    public static void printHelp() {
        String help =
                "usage: file_encriptor.py [-h] [-i INIT] | [-k KEYFILE [-e ENCRIPT] | [-d DECRIPT] [-v] [-s]]\n\n"
                + "parsa - PAssword RSA. Encript and Decript contents of files via RSA algorithm. The private key is a password of your choosing.\n"
                + "-h, --help                       show this help message and exits.\n"
                + "-i INIT, --init INIT             Init a keyfile, name of keyfile.\n"
                + "-k KEYFILE, --keyfile KEYFILE    Encription and Decription mode, name of keyfile.\n"
                + "-e ENCRIPT, --encript ENCRIPT    Encription mode, name of file to encript.\n"
                + "-d DECRIPT, --decript DECRIPT    Decription mode, name of file to decript.\n\n"
                + "optional arguments:\n"
                + "-v, --verbose    Decription mode, print decripted file.\n"
                + "-s, --save             Decription mode, save decripted file.\n";

        System.out.println(help);
    }
}
