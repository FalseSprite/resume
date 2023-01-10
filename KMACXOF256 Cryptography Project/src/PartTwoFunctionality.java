import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Class supporting all functionality of part 2 of the project
 * @author Ethan Nesel(Except for those parts listed as outside sourced)
 */
public class PartTwoFunctionality {

    /**
     * Method to generate elliptic key pair and put it in a key file
     */
    public static void ellipticKeyPair() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacKey = new KMACXOF256();

        //Get password
        System.out.println("Enter password to create keys:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();

        //Private Key
        byte[] sPositive = new byte[65];
        byte[] sPartOne = kmacKey.KMACXOF256(pass.getBytes(), "".getBytes(), 512, "K".getBytes());
        System.arraycopy(sPartOne, 0, sPositive, 1, 64);
        BigInteger sValue = new BigInteger(sPositive);
        BigInteger sPartTwo = BigInteger.valueOf(4).multiply(sValue);

        //Public Key
        EllipticPoint G = new EllipticPoint(BigInteger.valueOf(4), false);
        EllipticPoint V = EllipticPoint.scale(sPartTwo, G);

        //Output public key components to file
        File publicKey = new File(pass + ".pub_key_file");
        System.out.println("Keys created\n");
        try {
            FileWriter myWriter = new FileWriter(publicKey);
            myWriter.write(V.getX().toString() + "\n");
            myWriter.write(V.getY().toString());
            myWriter.close();
            Menu.mainMenu();
        } catch (IOException e) {
            System.out.println("Error, returning to menu\n");
            Menu.mainMenu();
        }
    }

    /**
     * Method to create a cryptogram containing file for a file based on a public key pair and
     * the file itself
     */
    public static void ellipticFileEncrypt() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacEE = new KMACXOF256();

        //File Selection (the file to be encrypted)
        System.out.println("Select file to encrypt");
        File selected = Functions.selectFile();

        //Convert file input to byte array
        byte[] m = null;
        try {
            assert selected != null;
            m = Files.readAllBytes(selected.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file\n");
            Menu.mainMenu();
        }
        //Random(512) = k
        SecureRandom rand = new SecureRandom();
        byte[] kInitial = new byte[65];
        rand.nextBytes(kInitial);
        kInitial[0] = 0;
        //k = 4k
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(kInitial));
        //Initialize G
        EllipticPoint G = new EllipticPoint(BigInteger.valueOf(4), false);

        //File Selection for V (the public key file)
        System.out.println("Select public key file");
        File selectV = Functions.selectFile();

        BigInteger xComp = null;
        BigInteger yComp = null;

        try {
            Scanner scan = new Scanner(selectV);
            xComp = new BigInteger(scan.nextLine());
            yComp = new BigInteger(scan.nextLine());
            scan.close();
        } catch (FileNotFoundException e) {
            System.out.println("Error with file reading, returned to menu\n");
            Menu.mainMenu();
        }

        //Public Key
        assert xComp != null;
        EllipticPoint V = new EllipticPoint(xComp, yComp);
        //k*V
        EllipticPoint W = EllipticPoint.scale(k, V);
        //k*G
        EllipticPoint Z = EllipticPoint.scale(k, G);

        //(ke || ka) <- KMACXOF256(wSubX, “”, 1024, “P”)
        byte[] wSubX = W.getX().toByteArray();
        byte[] kellka = kmacEE.KMACXOF256(wSubX, "".getBytes(), 1024, "P".getBytes());

        //c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] ke = Arrays.copyOfRange(kellka, 0,64);
        byte[] cPartOne  = kmacEE.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
        byte[] c = new byte[m.length];

        for (int j = 0; j < m.length; j++) {
            c[j] =  (byte)(m[j] ^ cPartOne[j]);
        }
        //t <- KMACXOF256(ka, m, 512, “PKA”)
        byte[] ka = Arrays.copyOfRange(kellka, 64,128);
        byte[] t  = kmacEE.KMACXOF256(ka, m, 512, "PKA".getBytes());

        //Output
        String fileNameWithOutExt = selected.getName().replaceFirst("[.][^.]+$", "");
        File cryptogram = new File(fileNameWithOutExt + ".encrypted_schnorr_ecdhies");
        try {
            FileWriter myWriter = new FileWriter(cryptogram);
            myWriter.write(Z.getX().toString() + "\n");
            myWriter.write(Z.getY().toString() + "\n");
            myWriter.write(Functions.bytesToHex(c) + "\n");
            myWriter.write(Functions.bytesToHex(t));
            myWriter.close();
            System.out.println("Successfully created cryptogram\n");
            Menu.mainMenu();
        } catch (IOException e) {
            System.out.println("Could not print to that file, returning to menu\n");
            Menu.mainMenu();
        }
    }

    /**
     * Method to decrypt the elliptic cryptogram using the password and cryptogram
     */
    public static void ellipticFileDecrypt() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacED = new KMACXOF256();

        //Get password
        System.out.println("Enter password used in creating public key:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();

        //File Selection
        System.out.println("Select cryptogram file to decrypt");
        File selected = Functions.selectFile();
        Scanner fileScanner = null;
        try {
            assert selected != null;
            fileScanner = new Scanner(selected);
        } catch (FileNotFoundException e) {
            System.out.println("File not found returning to menu\n");
            Menu.mainMenu();
        }

        //Convert Zct to variables
        assert fileScanner != null;
        BigInteger zX = new BigInteger(fileScanner.next());
        BigInteger zY = new BigInteger(fileScanner.next());
        EllipticPoint Z = new EllipticPoint(zX,zY);
        byte[] cBytes = Functions.hexStringToByteArray(fileScanner.next());
        byte[] tBytes = Functions.hexStringToByteArray(fileScanner.next());


        //s <- KMACXOF256(pw, “”, 512, “K”)
        byte[] sPositive = new byte[65];
        byte[] sPartOne = kmacED.KMACXOF256(pass.getBytes(), "".getBytes(),
                512, "K".getBytes());
        System.arraycopy(sPartOne, 0, sPositive, 1, 64);

        //s <- 4s
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(sPositive));
        //W <- s * Z
        EllipticPoint W = EllipticPoint.scale(s, Z);

        //(ke || ka) <- KMACXOF256(Wx, “”, 1024, “P”)
        byte[] kellka = kmacED.KMACXOF256(W.getX().toByteArray(),
                "".getBytes(), 1024, "P".getBytes());

        //m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
        byte[] ke = Arrays.copyOfRange(kellka, 0,64);
        byte[] mPartOne  = kmacED.KMACXOF256(ke, "".getBytes(),
                (cBytes.length * 8), "PKE".getBytes());

        byte[] m = new byte[cBytes.length];
        for (int j = 0; j < cBytes.length; j++) {
            m[j] =  (byte)(mPartOne[j] ^ cBytes[j]);
        }

        //t’ <- KMACXOF256(ka, m, 512, “PKA”)
        byte[] ka = Arrays.copyOfRange(kellka, 64,128);
        byte[] tPrime  = kmacED.KMACXOF256(ka, m, 512, "PKA".getBytes());

        //Output condition
        if (Arrays.equals(tPrime, tBytes)) {
            //Output
            String fileNameWithOutExt = selected.getName().replaceFirst("[.][^.]+$", "");
            File cryptogram = new File(fileNameWithOutExt + ".decodedECC");
            try {
                FileWriter myWriter = new FileWriter(cryptogram);
                myWriter.write((new String(m, StandardCharsets.UTF_8)));
                myWriter.close();
                System.out.println("Successfully decoded cryptogram\n");
                Menu.mainMenu();
            } catch (IOException e) {
                System.out.println("Could not print to that file, returning to menu\n");
                Menu.mainMenu();
            }
        } else {
            System.out.println("Mismatch detected, NOT ACCEPTED\n");
            Menu.mainMenu();
        }
    }

    /**
     * Signature generator method that takes in a password and file and outputs
     * a signature file
     */
    public static void signatureGen() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacSG = new KMACXOF256();

        //Get password
        System.out.println("Enter password to sign with:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();

        //File Selection
        System.out.println("Select a file to generate a signature for");
        File selected = Functions.selectFile();

        //Convert file input to byte array
        byte[] m = null;
        try {
            assert selected != null;
            m = Files.readAllBytes(selected.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file\n");
            Menu.mainMenu();
        }
        //s <- KMACXOF256(pw, “”, 512, “K”)
        byte[] sPos = new byte[65];
        byte[] sPartOne = kmacSG.KMACXOF256(pass.getBytes(), "".getBytes(),
                512, "K".getBytes());
        System.arraycopy(sPartOne, 0, sPos, 1, 64);
        //s <- 4s
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(sPos));
        //k <- KMACXOF256(s, m, 512, “N”)
        byte[] kPos = new byte[65];
        byte[] kPartOne = kmacSG.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes());
        System.arraycopy(kPartOne, 0, kPos, 1, 64);
        //k <- 4k
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(kPos));
        //Initialize G
        EllipticPoint G = new EllipticPoint(BigInteger.valueOf(4), false);
        //U <- k*G;
        EllipticPoint U = EllipticPoint.scale(k,G);

        //h <- KMACXOF256(Ux, m, 512, “T”)
        byte[] hPos = new byte[65];
        byte[] h = kmacSG.KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes());
        System.arraycopy(h, 0, hPos, 1, 64);
        //z <- (k – hs) mod r
        BigInteger rPartOne = new BigInteger("2").pow(519);
        BigInteger rPartTwo = new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
        BigInteger r = rPartOne.subtract(rPartTwo);
        BigInteger z = (k.subtract(new BigInteger(hPos).multiply(s))).mod(r);

        //Output
        String fileNameWithOutExt = selected.getName().replaceFirst("[.][^.]+$", "");
        File cryptogram = new File(fileNameWithOutExt + ".signature");
        try {
            FileWriter myWriter = new FileWriter(cryptogram);
            myWriter.write(Functions.bytesToHex(h) + "\n");
            myWriter.write(z.toString());
            myWriter.close();
            System.out.println("Successfully created signature file\n");
            Menu.mainMenu();
        } catch (IOException e) {
            System.out.println("Could not print to that file, returning to menu\n");
            Menu.mainMenu();
        }

    }

    /**
     * Method to verify a signature for a file under a public key
     */
    public static void verifySig() {
        KMACXOF256 kmacVS = new KMACXOF256();
        //Select file to be verified
        System.out.println("Select a file to try and verify");
        File fileToVer = Functions.selectFile();
        //Convert file input to byte array
        byte[] m = null;
        try {
            assert fileToVer != null;
            m = Files.readAllBytes(fileToVer.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file");
            Menu.mainMenu();
        }

        //Select public key file
        System.out.println("Select public key file");
        File pubKey = Functions.selectFile();
        BigInteger xComp = null;
        BigInteger yComp = null;
        try {
            Scanner scan = new Scanner(pubKey);
            xComp = new BigInteger(scan.nextLine());
            yComp = new BigInteger(scan.nextLine());
        } catch (FileNotFoundException e) {
            System.out.println("Error reading file\n");
            Menu.mainMenu();
        }

        assert xComp != null;
        EllipticPoint V = new EllipticPoint(xComp,yComp);

        //Select signature file
        System.out.println("Select signature file\n");
        File sigFile = Functions.selectFile();
        byte[] h = null;
        BigInteger z = null;

        try {
            Scanner sigRead = new Scanner(sigFile);
            h = Functions.hexStringToByteArray(sigRead.nextLine());
            z = sigRead.nextBigInteger();
        } catch (FileNotFoundException e) {
            System.out.println("Error reading file");
            Menu.mainMenu();
        }
        //Initialize G
        EllipticPoint G = new EllipticPoint(BigInteger.valueOf(4), false);
        //U <- z*G + h*V
        EllipticPoint zG = EllipticPoint.scale(z, G);
        byte[] hPos = new byte[65];
        System.arraycopy(h, 0, hPos, 1, 64);

        EllipticPoint hV = EllipticPoint.scale(new BigInteger(hPos), V);
        EllipticPoint U = zG.sum(hV);


        //accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
        byte[] hCompare = kmacVS.KMACXOF256(U.getX().toByteArray(), m,
                512, "T".getBytes());

        if (Arrays.equals(h, hCompare)) {
            System.out.println("Accepted\n");
            Menu.mainMenu();
        } else {
            System.out.println("Not Accepted\n");
            Menu.mainMenu();
        }
    }

}
