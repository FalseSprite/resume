/**
 * Class implementing shake to provide cSHAKE256
 * @author Qinyu Tao
 */
public class CSHAKE256 {

    /**
     * Compute cSHAKE256
     * @param X the main byte string
     * @param L the output length in bits
     * @param N a function-name bit string
     * @param S a customization bit string
     * @return  the desired hash value
     */
    /*Utilizing NIST.SP.800-185
     (with inspiration from the implementation shown in office hours) */
    public byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S){
        Sha3 shake = new Sha3();
        //Validity Conditions: len(N)< 2^2040 and len(S)< 2^2040
        boolean cType = false;
        byte[] output = new byte[L / 8];
        shake.sha3_init();
        if ((N != null && N.length != 0) || (S != null && S.length != 0)) {
            byte[] concatenated =
                    Functions.bytepad(Functions.concat(Functions.encode_string(N), Functions.encode_string(S)), 136);
            shake.sha3_update(concatenated, concatenated.length);
            cType = true;
        }
        shake.sha3_update(X,X.length);
        shake.shake_xof(cType);
        shake.shake_out(output, L / 8);
        return output;

    }

}
