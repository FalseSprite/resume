import java.nio.charset.StandardCharsets;

/**
 * KMACXOF256 Implementation
 * @author Ethan Nesel
 */
public class KMACXOF256 {
    /**
     * Invoke CSHAKE256
     */
    private final CSHAKE256 cshake256 = new CSHAKE256();
    /**
     * "KMAC" string used within the implementation
     */
    private static final String KMACString = "KMAC";

    /**
     * Compute KMACXOF256
     * @param K a key bit string
     * @param X the main input bit string
     * @param L the output length in bits
     * @param S an optional customization bit string
     * @return  the desired MAC tag
     */
    //Based on NIST pseudocode steps
    public byte[] KMACXOF256(byte[] K, byte[] X,  int L, byte[] S) {
        //Validity Conditions: len(K) <2^2040 and 0 ≤ L and len(S) < 2^2040
        byte[] newXpart1 = Functions.bytepad(Functions.encode_string(K), 136);
        byte[] newXpart2 = Functions.concat(newXpart1, X);
        byte[] newX = Functions.concat(newXpart2, Functions.right_encode(0));
        return cshake256.cSHAKE256(newX, L, KMACString.getBytes(StandardCharsets.UTF_8), S);
    }
}
