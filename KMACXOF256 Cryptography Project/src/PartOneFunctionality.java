import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * The PartOneFunctionality class provides the methods that
 * support all requirements listed in part 1 of the project
 * description.
 *
 * @author Ethan Nesel(Except for those parts listed as outside sourced)
 */
public class PartOneFunctionality {
    /**
     * Computes the plain cryptographic hash of a given file
     */
    public static void plainHashFile() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacForHashFile = new KMACXOF256();

        //File Selection
        System.out.println("Please select a file to hash.");
        File selectFileToHash = Functions.selectFile();
        //Convert file input to byte array
        byte[] m = null;
        try {
            assert selectFileToHash != null;
            m = Files.readAllBytes(selectFileToHash.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file.\n");
            Menu.mainMenu();
        }

        //h <- KMACXOF256(“”, m, 512, “D”)
        byte[] h = kmacForHashFile.KMACXOF256("".getBytes(), m, 512,"D".getBytes());
        System.out.println("Plain Hash of File Input: " + Functions.bytesToHex(h) + "\n");

        //Return to menu
        Menu.mainMenu();
    }

    /**
     * Computes a plain cryptographic hash of text input
     */
    public static void plainHashText() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacForHashText = new KMACXOF256();

        //Get user input to hash
        System.out.println("Enter text to hash:");
        Scanner userInput = new Scanner(System.in);
        String input = userInput.nextLine();


        //Convert text to byte array
        byte[] m = input.getBytes();

        //h <- KMACXOF256(“”, m, 512, “D”)
        byte[] h = kmacForHashText.KMACXOF256("".getBytes(), m, 512,"D".getBytes());
        System.out.println("Plain Hash of Text Input: " + Functions.bytesToHex(h) + "\n");
        //Return to main menu
        Menu.mainMenu();
    }

    /**
     * Encrypts a given data file symmetrically under a given
     * passphrase. The output takes the form of the file name + .crypto
     */
    public static void symmetricEncryptFile() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacSEncrypt = new KMACXOF256();

        //Get password
        System.out.println("Enter password to encrypt file with:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();


        //File Selection
        System.out.println("Select a file to encrypt.");
        File selectedToEncrypt = Functions.selectFile();

        //Convert file input to byte array
        byte[] m = null;
        try {
            assert selectedToEncrypt != null;
            m = Files.readAllBytes(selectedToEncrypt.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file.\n");
            Menu.mainMenu();
        }
        //Random(512)
        SecureRandom rand = new SecureRandom();
        byte[] z = new byte[64];
        rand.nextBytes(z);

        //(ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] pw = pass.getBytes();
        byte[] kellka = kmacSEncrypt.KMACXOF256(Functions.concat(z,pw),"".getBytes(), 1024,
                "S".getBytes());

        //c <- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] ke = Arrays.copyOfRange(kellka, 0,64);
        byte[] cPartOne  = kmacSEncrypt.KMACXOF256(ke, "".getBytes(), (m.length * 8),
                "SKE".getBytes());
        byte[] c = new byte[m.length];
        for (int j = 0; j < m.length; j++) {
            c[j] =  (byte)(cPartOne[j] ^ m[j]);
        }

        //t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] ka = Arrays.copyOfRange(kellka, 64,128);
        byte[] t  = kmacSEncrypt.KMACXOF256(ka, m, 512, "SKA".getBytes());

        //Output
        String fileNameWithOutExt = selectedToEncrypt.getName()
                .replaceFirst("[.][^.]+$", "");

        File cryptogram = new File(fileNameWithOutExt + ".crypto");
        try {
            FileWriter myWriter = new FileWriter(cryptogram);
            myWriter.write(Functions.bytesToHex(z) + "\n");
            myWriter.write(Functions.bytesToHex(c) + "\n");
            myWriter.write(Functions.bytesToHex(t));
            myWriter.close();
            System.out.println("Successfully created cryptogram\n");
            Menu.mainMenu();
        } catch (IOException e) {
            System.out.println("Error with creating cryptogram, returning to menu\n");
            Menu.mainMenu();
        }
    }

    /**
     * Decrypts a given symmetric cryptogram under a given
     * passphrase. The output takes the name of crypto file name + .decoded
     */
    public static void symmetricDecrypt() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacSDecrypt = new KMACXOF256();

        //Get password
        System.out.println("Enter password:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();

        //File Selection
        System.out.println("Select a cryptogram file to decrypt");
        File selectedToDecrypt = Functions.selectFile();
        Scanner fileScanner = null;
        try {
            assert selectedToDecrypt != null;
            fileScanner = new Scanner(selectedToDecrypt);
        } catch (FileNotFoundException e) {
            System.out.println("File not readable, returning to menu\n");
            Menu.mainMenu();
        }

        //Reformat cryptogram parts to byte arrays
        assert fileScanner != null;
        byte[] zBytes = Functions.hexStringToByteArray(fileScanner.next());
        byte[] cBytes = Functions.hexStringToByteArray(fileScanner.next());
        byte[] tBytes = Functions.hexStringToByteArray(fileScanner.next());
        fileScanner.close();

        //(ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] pw = pass.getBytes();
        byte[] kellka = kmacSDecrypt.KMACXOF256(Functions.concat(zBytes,pw),
                "".getBytes(), 1024, "S".getBytes());

        //m <- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
        byte[] ke = Arrays.copyOfRange(kellka, 0,64);
        byte[] mPartOne  = kmacSDecrypt.KMACXOF256(ke, "".getBytes(),
                (cBytes.length * 8), "SKE".getBytes());

        byte[] m = new byte[cBytes.length];
        for (int j = 0; j < m.length; j++) {
            m[j] =  (byte)(mPartOne[j] ^ cBytes[j]);
        }

        //t’ <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] ka = Arrays.copyOfRange(kellka, 64,128);
        byte[] tPrime  = kmacSDecrypt.KMACXOF256(ka, m, 512, "SKA".getBytes());

        //Output condition
        if (Arrays.equals(tPrime, tBytes)) {
            //Output
            String fileNameWithOutExt = selectedToDecrypt.getName()
                    .replaceFirst("[.][^.]+$", "");

            File decryptedCryptogram = new File(fileNameWithOutExt + ".decrypted");
            try {
                FileWriter myWriter = new FileWriter(decryptedCryptogram);
                myWriter.write((new String(m, StandardCharsets.UTF_8)));
                myWriter.close();
                System.out.println("Successfully decrypted file\n");
                Menu.mainMenu();
            } catch (IOException e) {
                System.out.println("Error creating output, returning to menu\n");
               Menu.mainMenu();
            }
        } else {
            System.out.println("Mismatch detected, NOT ACCEPTED\n");
            Menu.mainMenu();
        }
    }

    /**
     * Compute an authentication tag (MAC) of a given file
     * under a given passphrase.
     */
    public static void authTag() {
        //Initialize a fresh KMACXOF256
        KMACXOF256 kmacTag = new KMACXOF256();

        //Get password
        System.out.println("Enter password for auth tag creation:");
        Scanner userInput = new Scanner(System.in);
        String pass = userInput.nextLine();


        //File Selection
        System.out.println("Select a file to create an auth tag for");
        File selectedForAuth = Functions.selectFile();

        //Convert file input to byte array
        byte[] m = null;
        try {
            assert selectedForAuth != null;
            m = Files.readAllBytes(selectedForAuth.toPath());
        } catch (IOException e) {
            System.out.println("Could not read from file\n");
            Menu.mainMenu();
        }
        //Create tag t <- KMACXOF256(pw, m, 512, “T”)
        byte[] pw = pass.getBytes();
        byte[] tag  = kmacTag.KMACXOF256(pw, m, 512, "T".getBytes());
        System.out.println("Tag: " + Functions.bytesToHex(tag) +"\n");
        Menu.mainMenu();
    }
}
