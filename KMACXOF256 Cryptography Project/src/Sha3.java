//All methods derived from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c

/**
 * Sha3 Implementation used for SHAKE to enable CSHAKE and KMAC
 * @Author Markku-Juhani O. Saarinen <mjos@iki.fi>
 * @Author Ethan Nesel(Except for parts attributed to outside sources/office hours)
 */
public class Sha3 {

    //Rounds
    private static final int KECCAK_ROUNDS = 24;

    //State context
    private byte[] b = new byte[200];

    private int pt;
    private int rsiz;
    private int mdlen;

    private static final long[] KECCAK_RNDC = {0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L,
            0x8000000000008009L, 0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L,
            0x000000008000000AL, 0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL,
            0x800000008000000AL, 0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L,
            0x8000000080008008L};


    private static final int[] KECCAKF_ROTC = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

    private static final int[] KECCAKF_PILN = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};


    /**
     * KECCAK-f
     * @param st state
     */
    private static void sha3_keccakf(byte[] st) {
        int byteShift = 0;
        long[] q = new long[25];
        //Byte to long conversion from office hour discussion
        for (int i = 0; i < 25; i++) {
            q[i] =  ((long) st[byteShift] & 0xFFL) |
                    (((long) st[byteShift + 1] & 0xFFL) << 8) |
                    (((long) st[byteShift + 2] & 0xFFL) << 16) |
                    (((long) st[byteShift + 3] & 0xFFL) << 24) |
                    (((long) st[byteShift + 4] & 0xFFL) << 32) |
                    (((long) st[byteShift + 5] & 0xFFL) << 40) |
                    (((long) st[byteShift + 6] & 0xFFL) << 48) |
                    (((long) st[byteShift + 7] & 0xFFL) << 56);
            byteShift += 8;
        }
        long[] bc = new long[5];
        long t = 0L;

        //Iteration
        for (int r = 0; r < KECCAK_ROUNDS; r++) {

            //Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10]
                        ^ q[i + 15] ^ q[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    q[j + i] ^= t;
                }
            }

            //Rho Pi
            t = q[1];
            for (int i = 0; i < 24; i++) {
                int j = KECCAKF_PILN[i];
                bc[0] = q[j];
                q[j] = ROTL64(t, KECCAKF_ROTC[i]);
                t = bc[0];
            }

            //Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = q[j + i];
                }
                for (int i = 0; i < 5; i++) {
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            //Iota
            q[0] ^= KECCAK_RNDC[r];
        }
        byteShift = 0;
        //Long to byte conversion from office hour discussion
        for (int i = 0; i < 25; i++) {
            long currentLong = q[i];
            st[0 + byteShift] = (byte) (currentLong & 0xFFL);
            st[1 + byteShift] = (byte) ((currentLong >> 8) & 0xFFL);
            st[2 + byteShift] = (byte) ((currentLong >> 16) & 0xFFL);
            st[3 + byteShift] = (byte) ((currentLong >> 24) & 0xFFL);
            st[4 + byteShift] = (byte) ((currentLong >> 32) & 0xFFL);
            st[5 + byteShift] = (byte) ((currentLong >> 40) & 0xFFL);
            st[6 + byteShift] = (byte) ((currentLong >> 48) & 0xFFL);
            st[7 + byteShift] = (byte) ((currentLong >> 56) & 0xFFL);
            byteShift = byteShift + 8;
        }
    }

    /**
     * Rotate x by y to the left
     * @param x first input
     * @param y second input
     * @return rotated value
     */
    private static long ROTL64(long x, int y) {
        return (x << y) | (x >>> (64-y));
    }

    /**
     * Initialize SHAKE256
     */
    public void sha3_init() {
        this.pt = 0;
        this.mdlen = 32;
        this.rsiz = 200 - 2 * mdlen;

    }

    /**
     * Update SHAKE256
     * @param data the input data
     * @param len the length
     */
    public void sha3_update(byte[] data, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            b[j++] ^= data[i];
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
        }
        pt = j;
    }

    /**
     * Absorb
     * @param type CSHAKE or SHAKE boolean
     */
    public void shake_xof(boolean type) {
        //Shake suffix values https://en.wikipedia.org/wiki/SHA-3
        if (type) {
            b[pt] ^= (byte)0x04;
        } else {
            b[pt] ^= (byte)0x1F;
        }
        b[rsiz - 1] ^= (byte)0x80;
        sha3_keccakf(b);
        pt = 0;
    }

    /**
     * Squeeze
     * @param out hash value
     * @param len squeezed byte total
     */
    public void shake_out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if(j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            out[i] = b[j++];
        }

        pt = j;
    }
}
