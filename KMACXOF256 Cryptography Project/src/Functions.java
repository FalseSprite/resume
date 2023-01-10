import javax.swing.*;
import java.io.File;

/**
 * The Functions class holds the supporting functions for implementing
 * KMACXOF256 and some other various helpers (file reading, etc)
 *
 * @author Ethan Nesel(except for the parts attributed to sourced online material/office hours)
 * @author Paulo Barreto(for those methods listed as taken from course material)
 */
public class Functions {
    /**
     * Hex Value Key
     */
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Right encode function
     *
     * @param input the number to be right encoded
     * @return a byte string or array representing the right encoded input
     */
    //Utilizing NIST.SP.800-185
    public static byte[] right_encode(int input) {
        //Validity Conditions: 0 ≤ input < 2^2040
        int n = 1;
        while (input >= Math.pow(256, n)) {
            n = n + 1;
        }
        int shifter = (n - 1) * 8;
        byte[] output = new byte[n + 1];
        for (int i = 0; i < n; i++) {
            output[i] = (byte) ((input >> shifter) & 0xff);
            shifter = shifter - 8;
        }
        output[n] = (byte) (n);
        return output;
    }

    /**
     * Left encode function
     *
     * @param input the number to be right encoded
     * @return a byte string or array representing the left encoded input
     */
    //Utilizing NIST.SP.800-185
    public static byte[] left_encode(int input) {
        //Validity Conditions: 0 ≤ input < 2^2040;
        int n = 1;
        while (input >= Math.pow(256, n)) {
            n = n + 1;
        }
        int shifter = (n - 1) * 8;
        byte[] output = new byte[n + 1];
        output[0] = (byte) (n);

        for (int i = 1; i <= n; i++) {
            output[i] = (byte) ((input >> shifter) & 0xff);
            shifter = shifter - 8;
        }
        return output;
    }

    /**
     * Prepends an encoding of the integer w to an input string X, then pads
     * the result with zeros until it is a byte string whose length in bytes is a multiple of w
     *
     * @param X the input string
     * @param w the integer we will encode and prepend to X
     * @return the bytepadded byte string or array
     */
    //Directly implemented from course slides, KMACXOF256.pdf slide 8 in canvas.
    public static byte[] bytepad(byte[] X, int w) {
        assert w > 0;
        byte[] encodedW = left_encode(w);
        byte[] z = new byte[w * ((encodedW.length + X.length + w - 1) / w)];
        System.arraycopy(encodedW, 0, z, 0, encodedW.length);
        System.arraycopy(X, 0, z, encodedW.length, X.length);

        for (int i = encodedW.length + X.length; i < z.length; i++) {
            z[i] = (byte) (0);
        }

        return z;
    }

    /**
     * The encode_string function is used to encode bit strings in a way that may be parsed
     * unambiguously from the beginning of the string, S.
     *
     * @param S the string to encode
     * @return the encoded string
     */
    /*Utilizing NIST.SP.800-185
     (with inspiration from the same function shown in office hours) */
    public static byte[] encode_string(byte[] S) {
        //Validity Conditions: 0 ≤ len(S) < 2^2040
        int lengthHolder = 0;
        if (S != null) {
            lengthHolder = S.length;
        }
        byte[] encodedS = left_encode(lengthHolder * 8);
        byte[] output = new byte[encodedS.length + lengthHolder];

        System.arraycopy(encodedS, 0, output, 0, encodedS.length);
        if (S != null) {
            System.arraycopy(S,0,output,encodedS.length,lengthHolder);
        }
        return output;
    }

    /**
     * concatenate two byte arrays
     *
     * @param one first array of concatenate
     * @param two second array of concatenate
     * @return the concatenated array
     */
    public static byte[] concat(byte[] one, byte[] two) {
        int lengthOfOne = one.length;
        int lengthOfTwo = two.length;
        if (lengthOfOne==0){
            return two;
        }
        if (lengthOfTwo==0){
            return one;
        }
        byte[] result = new byte[lengthOfOne + lengthOfTwo];
        System.arraycopy(one, 0, result, 0, lengthOfOne);
        System.arraycopy(two, 0, result, lengthOfOne, lengthOfTwo);
        return result;
    }

    /**
     * Simple byte array to hex string conversion
     * @param bytes byte array to be converted
     * @return hex-style string representing the given input
     */
    //Byte to hex converter implemented from
    //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Hex string to byte array converter
     * @param s the hex string to be converted
     * @return byte array representing the given input
     */
    //Hex to byte converter implemented from
    //https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        if (s == null) {
            return null;
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Simple file selector to prevent duplicate code
     * @return file selected
     */
    public static File selectFile() {
        File selected = null;
        JFileChooser fileSelect = new JFileChooser();
        int didSelect = fileSelect.showOpenDialog(null);

        if (didSelect == JFileChooser.APPROVE_OPTION) {
            selected = fileSelect.getSelectedFile();
        } else {
            System.out.println("No File Selected\n");
            Menu.mainMenu();
        }
        return selected;
    }
}
