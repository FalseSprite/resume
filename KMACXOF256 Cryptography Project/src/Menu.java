import java.util.Scanner;

/**
 * Menu class contains the navigation instructions and most I/O relating
 * to such.
 * @Author Ethan Nesel
 */
public class Menu {

    /**
     * Main starts the program
     * @param args CLA (unused)
     */
    public static void main(String[] args) {
        mainMenu();
    }

    /**
     * Controls the user input for main menu selection
     */
    public static void mainMenu() {
        Scanner menuScan = new Scanner(System.in);
        welcomeMessage();
        int number;
        do {
            System.out.println("Enter a valid selection:");
            while (!menuScan.hasNextInt()) {
                System.out.println("That's not even an integer!");
                menuScan.next(); // this is important!
            }
            number = menuScan.nextInt();
        } while (number > 11 || number < 1);
        switch (number) {
            case 1 -> PartOneFunctionality.plainHashFile();
            case 2 -> PartOneFunctionality.plainHashText();
            case 3 -> PartOneFunctionality.symmetricEncryptFile();
            case 4 -> PartOneFunctionality.symmetricDecrypt();
            case 5 -> PartOneFunctionality.authTag();
            case 6 -> PartTwoFunctionality.ellipticKeyPair();
            case 7 -> PartTwoFunctionality.ellipticFileEncrypt();
            case 8 -> PartTwoFunctionality.ellipticFileDecrypt();
            case 9 -> PartTwoFunctionality.signatureGen();
            case 10 -> PartTwoFunctionality.verifySig();
            case 11 -> System.exit(1);
            default -> mainMenu();
        }
    }

    /**
     * Main menu welcome messages
     */
    public static void welcomeMessage() {
        System.out.println("Welcome to the 487 Project Menu, please type the number of an option");
        System.out.println("1 Compute Plain Crypto Hash of a File");
        System.out.println("2 Compute Plain Crypto Hash of a Text Input");
        System.out.println("3 Encrypt a Data File Symmetrically");
        System.out.println("4 Decrypt a Symmetric Cryptogram");
        System.out.println("5 Compute MAC of a given file");

        System.out.println("6 Generate Elliptic Key Pair");
        System.out.println("7 Encrypt a file under Schnorr/ECDHIES");
        System.out.println("8 Decrypt a file under Schnorr/ECDHIES");
        System.out.println("9 Create a signature for a file");
        System.out.println("10 Verify a signature");
        System.out.println("\nEnter 11 to exit");
    }
}
