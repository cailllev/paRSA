package ch.zhaw.cailllev;

import static ch.zhaw.cailllev.Utils.*;

import org.mindrot.jbcrypt.BCrypt;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Main {

    protected static final String ENCRYPTED_EXTENSION = ".parsa";
    protected static final String KEYFILE_EXTENSION = ".pub";

    private static final String HEADER_KEYFILE = "======== BEGIN PUBLIC KEYFILE - PARSA ========\n";
    private static final String TAIL_KEYFILE = "========= END PUBLIC KEYFILE - PARSA =========\n";

    private static final int HASH_ROUNDS = 16; //2^16
    private static final int LENGTH_N = 2048;

    protected static BigInteger[] initKeyfile(String name, String password, int lengthN, int hashRounds) {
        String keyfileOutName = name + KEYFILE_EXTENSION;
        File keyfile = new File(keyfileOutName);
        if (keyfile.exists()) {
            System.out.println("[!] Keyfile " + keyfileOutName + " already exists.");
            System.exit(1);
        }

        // test if in debug / testing mode
        boolean debug;
        if (password == null) {
            debug = false;
            lengthN = LENGTH_N;
            hashRounds = HASH_ROUNDS;
        } else {
            debug = true;
        }

        if (debug) {
            if (lengthN < 32) {
                System.out.println("[!] Length of n has to be at least 32 bit, functionality wise.");
                System.exit(1);
            }
        }
        else if (lengthN < LENGTH_N) {
            System.out.println("[!] Length of n has to be at least 2048 bit, security wise.");
            System.exit(1);
        }

        //   100000000 // number
        // & 011111111 // number - 1
        // -----------
        //   000000000
        if ((lengthN & (lengthN - 1)) != 0) {
            System.out.println("[!] Length of n must be power of 2 (2048, 4096, ...).");
            System.exit(1);
        }

        System.out.println("[*] Create keyfile with " + lengthN + " bits and " + hashRounds
                + " hash rounds.");

        SecureRandom secRandom = new SecureRandom();
        int delta = 5 + secRandom.nextInt(10);
        int lengthP = lengthN / 2 + delta;
        int lengthQ = lengthN - lengthP + 1;

        safePrimeBM(lengthN / 2);
        BigInteger p = safePrime(lengthP);
        BigInteger q = safePrime(lengthQ);

        BigInteger n = p.multiply(q);
        BigInteger ONE = BigInteger.ONE;
        BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE));

        if (!debug) {
            while (true) {
                System.out.println("[*] Please enter the password to use for the encryption: ");
                password = new String(System.console().readPassword());

                if (!checkPasswordStrength(password)) {
                    continue;
                }

                System.out.println("[*] Please re-enter the password: ");
                String passwordCheck = new String(System.console().readPassword());

                if (passwordCheck.equals(password)) {
                    System.out.println("[*] Successfully created password.");
                    break;
                }
                else {
                    System.out.println("[!] Passwords did not match, please try again.");
                }
            }
        }

        String salt = null;
        try {
            salt = BCrypt.gensalt(hashRounds);
        }

        catch (Exception ex) {
            System.out.println("[!] Internal BCrypt error.");
            System.exit(1);
        }

        BigInteger dIn  = getNumFromPassword(password, lengthN, salt);
        int bitDiff = lengthN - dIn.bitLength();

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

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(keyfileOutName))) {
            writer.write(HEADER_KEYFILE);
            writer.write(n.toString() + ":" + lengthN + "\n");
            writer.write(e.toString() + "\n");
            writer.write(salt + ":" + quotient.toString() + ":" + remainder.toString() + "\n");
            writer.write(TAIL_KEYFILE);
        }

        catch (IOException ex) {
            System.out.println("[!] IOException when writing to keyfile " + keyfileOutName + ".");
            System.exit(1);
        }

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

    protected static void encrypt(String filename, String keyfileName) {
        String outfileName = filename + ENCRYPTED_EXTENSION;

        File outfile = new File(outfileName);
        if (outfile.exists()) {
            System.out.println("[!] Encrypted outfile " + outfileName + " already exists.");
            System.exit(1);
        }

        KeyfileContent kC = parseKeyfile(keyfileName);
        BigInteger n = kC.getN();
        int lengthN = kC.getLengthN();
        BigInteger e = kC.getE();

        byte[] data = new byte[0];
        try {
            data = Files.readAllBytes(Path.of(filename));

        } catch (IOException ex) {
            System.out.println("[!] IOException when reading file to encrypt " + filename + ".");
            System.exit(1);
        }

        byte[][] mBytes = toChunks(data, lengthN);

        //m^e mod n
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outfileName))) {
            BigInteger m, c;
            for (byte[] bytes : mBytes) {
                m = new BigInteger(1, bytes);
                c = m.modPow(e, n);

                writer.write(c.toString() + "\n");
            }

        } catch (IOException ex) {
            System.out.println("[!] IOException when writing cipher to " + outfileName + ".");
            System.exit(1);
        }

        System.out.println("[*] Successfully encrypted contents of " + filename + " and saved them under " + outfile);
    }

    protected static void decrypt(String filename, String keyfileName, boolean show, boolean save, String password) {

        KeyfileContent kC = parseKeyfile(keyfileName);
        BigInteger n = kC.getN();
        int lengthN = kC.getLengthN();
        String salt = kC.getSalt();
        BigInteger quotient = kC.getQuotient();
        BigInteger remainder = kC.getRemainder();

        if (password == null) {
            System.out.println("[*] Please enter your password: ");
            password = new String(System.console().readPassword());
        }

        // d + diff = real d
        // qout = diff / d
        // rem = diff % d
        // => diff = d*qout + rem
        // => real d = d + d*qout + rem
        BigInteger d = getNumFromPassword(password, lengthN, salt);
        d = d.add(quotient.multiply(d)).add(remainder);

        List<String> data = null;
        try {
            data = Files.readAllLines(Path.of(filename));

        } catch (IOException ex) {
            System.out.println("[!] IOException when reading the file to encrypt " + filename + ".");
            System.exit(1);
        }

        // #c^d mod n
        ArrayList<Byte> plain = new ArrayList<>();
        for (String cS : data) {
            BigInteger c = new BigInteger(cS);

            BigInteger m = c.modPow(d, n);

            for (Byte b : m.toByteArray()) {
                plain.add(b);
            }
        }

        // remove padding, i.e. trailing 0 bytes
        int i = plain.size() - 1;
        while (plain.get(i) == 0) {
            plain.remove(i);
            i--;
        }

        byte[] plainArray = new byte[plain.size()];
        for(int j = 0; j < plain.size(); j++) {
            plainArray[j] = plain.get(j);
        }

        System.out.println("[*] Successfully decripted contents of " + filename + ".");

        if (show) {
            String plainDecoded = new String(plainArray, StandardCharsets.US_ASCII);
            boolean canBeShown = StandardCharsets.US_ASCII.newEncoder().canEncode(plainDecoded);

            if (canBeShown) {
                System.out.println("[*] Result of decription see below.");
                System.out.println("*******************************");
                System.out.println(plainDecoded);
                System.out.println("*******************************");
            } else {
                System.out.println("[*] The plain text cannot be shown (not in ASCII format).");

                if (!save) {
                    System.out.println("[*] The plain text is cuurently not getting saved, save it? [Y/n]");

                    try {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                        String ans = reader.readLine();
                        if (ans.equals("Y") || ans.equals("y") || ans.equals("")) {
                            save = true;
                        }

                    } catch (IOException ex) {
                        System.out.println("[!] IOException when reading from stdin.");
                        System.exit(1);
                    }
                }
            }
        }

        if (save) {
            String outfileName = filename.substring(0, filename.length() - ENCRYPTED_EXTENSION.length());

            File outfile = new File(outfileName);
            if (outfile.exists()) {
                System.out.println("[!] Decripted outfile " + outfile + " already exists.");
                System.exit(1);
            }

            try (FileOutputStream fos = new FileOutputStream(outfileName)) {
                fos.write(plainArray);

            } catch (IOException ex) {
                System.out.println("[!] Error when writing plain text to outfile " + outfile + ".");
                System.exit(1);
            }

            System.out.println("[*] Contents saved in " + outfile + ".");
        }
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
     * @param args the command line arguments for the program
     */
    public static void main(String[] args) {
        parse(args);
    }

    private static void parse(String[] args) {
        if (args.length == 0) {
            printHelp();
            return;
        }

        switch (args[0]) {
            case "-h", "--help" -> printHelp();
            case "-i", "--init" -> {
                if (args.length < 2) {
                    System.out.println("******************************************************************");
                    System.out.println("If the keyfile flag is set, the name of it has to be supplied too!");
                    System.out.println("******************************************************************\n");
                    printHelp();
                }

                String keyfileName = args[1];
                System.out.println("[*] Init keyfile: " + keyfileName);
                initKeyfile(keyfileName, null, 0, 0);
            }
            case "-k", "--keyfile" -> {
                if (args.length < 2) {
                    System.out.println("******************************************************************");
                    System.out.println("If the keyfile flag is set, the name of it has to be supplied too!");
                    System.out.println("******************************************************************\n");
                    printHelp();
                }
                if (args.length < 3) {
                    System.out.println("**********************************************************************");
                    System.out.println("If the keyfile is set, the encryption or decryption has to be set too!");
                    System.out.println("**********************************************************************\n");
                    printHelp();
                }
                String keyfile_name = args[1];

                if (args[2].equals("-e") || args[2].equals("--encrypt")) {
                    if (args.length < 4) {
                        System.out.println("**************************************************************************************************");
                        System.out.println("If the keyfile and encryption flag is set, the name of the file to encrypt has to be supplied too!");
                        System.out.println("**************************************************************************************************\n");
                        printHelp();
                    }

                    String file = args[3];
                    System.out.println("[*] Encrypt: " + file);

                    encrypt(file, keyfile_name);
                } else if (args[2].equals("-f") || args[2].equals("--decript")) {
                    if (args.length < 4) {
                        System.out.println("**************************************************************************************************");
                        System.out.println("If the keyfile and decryption flag is set, the name of the file to decrypt has to be supplied too!");
                        System.out.println("**************************************************************************************************\n");
                        printHelp();
                    }

                    String file = args[3];
                    System.out.println("[*] Decript: " + file);

                    boolean show= false, save = false;

                    if (args.length == 5) {
                        show = args[4].equals("-v") || args[4].equals("--verbose");
                        save = args[4].equals("-s") || args[4].equals("--save");
                    }

                    else if (args.length == 6) {
                        show = args[4].equals("-v") || args[4].equals("--verbose")
                                || args[5].equals("-v") || args[5].equals("--verbose");
                        save = args[4].equals("-s") || args[4].equals("--save")
                                || args[5].equals("-s") || args[5].equals("--save");
                    }

                    System.out.println("[*] Show decrypted: " + show);
                    System.out.println("[*] Save decrypted: " + save);

                    decrypt(file, keyfile_name, show, save, null);
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

    private static void printHelp() {
        String help =
                "usage: file_encryptor.py [-h] [-i INIT] | [-k KEYFILE [-e ENCRYPT] | [-d DECRIPT] [-v] [-s]]\n\n"
                + "parsa - PAssword RSA. Encrypt and Decript contents of files via RSA algorithm. The private key is a password of your choosing.\n"
                + "-h, --help                       show this help message and exits.\n"
                + "-i INIT, --init INIT             Init a keyfile, name of keyfile.\n"
                + "-k KEYFILE, --keyfile KEYFILE    Encryption and Decription mode, name of keyfile.\n"
                + "-e ENCRYPT, --encrypt ENCRYPT    Encryption mode, name of file to encrypt.\n"
                + "-d DECRIPT, --decript DECRIPT    Decription mode, name of file to decript.\n\n"
                + "optional arguments:\n"
                + "-v, --verbose    Decription mode, print decripted file.\n"
                + "-s, --save             Decription mode, save decripted file.\n";

        System.out.println(help);
        System.exit(1);
    }
}
