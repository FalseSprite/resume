import java.math.BigInteger;

/**
 * Class utilized to represent points used for E521 elliptic cryptography
 * @author Ethan Nesel (except for those parts inspired by listed sources)
 * @author Paulo Barreto(for those methods taken from the project descriptions and slides)
 */
public class EllipticPoint {
    /**
     * The x-coordinate
     */
    private BigInteger x;
    /**
     * The y-coordinate
     */
    private BigInteger y;
    /**
     * The Mersenne prime used as the modulus
     */
    public static final BigInteger p = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    /**
     * The value d in the E521 curve equation
     */
    private static final BigInteger d = BigInteger.valueOf(-376014);

    /**
     * Constructor for neutral element
     */
    public EllipticPoint() {
        x = BigInteger.ZERO;
        y = BigInteger.ONE;
    }

    /**
     * Constructor for point given x and y
     * @param x coordinate x
     * @param y coordinate y
     */
    public EllipticPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    /**
     * Constructor for point given x and lsb
     * @param x coordinate x
     * @param lsb least significant bit of y
     */
    public EllipticPoint(BigInteger x, boolean lsb) {
        //𝑦=±√(1−𝑥2)/(1+376014𝑥2) mod 𝑝
        this.x = x;
        BigInteger dPos = new BigInteger("376014");
        BigInteger xSquared = (x.modPow(BigInteger.TWO,p));

        BigInteger num = (BigInteger.ONE.subtract(xSquared)).mod(p);
        BigInteger denPart = (dPos.multiply(xSquared)).mod(p);
        BigInteger den = (BigInteger.ONE.add(denPart)).mod(p);
        this.y = sqrt(num.multiply(den.modInverse(p)).mod(p), lsb);

    }

    /**
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     *
     * @param   v   the radicand.
     * @param   lsb desired least significant bit (true: 1, false: 0).
     * @return  a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *          if such a root exists, otherwise null.
     */
    //Method taken directly from project description
    public static BigInteger sqrt(BigInteger v, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Getter for x-coordinate
     * @return the value of the x-coordinate
     */
    public BigInteger getX() {
        return x;
    }

    /**
     * Getter for y-coordinate
     * @return the value of the y-coordinate
     */
    public BigInteger getY() {
        return y;
    }

    /**
     * Equals method to compare two points
     * @param pt the point to compare against
     * @return true if equal and false if not
     */
    public boolean equals(EllipticPoint pt) {
        return this.x.equals(pt.getX()) && this.y.equals(pt.getY());
    }

    /**
     * Compute the opposite of a point
     * @return the opposite of the point the method is applied to
     */
    public EllipticPoint opposite() {
        return new EllipticPoint(BigInteger.valueOf(-1).multiply(this.x), this.y);
    }

    /**
     * Sum two points
     * @param pt the other point to sum with the current
     * @return the summed point result
     */
    public EllipticPoint sum(EllipticPoint pt){
        BigInteger xOne = this.getX();
        BigInteger yOne = this.getY();
        BigInteger xTwo = pt.getX();
        BigInteger yTwo = pt.getY();

        //The parts of the Edwards point addition formula
        //Notice we must mod each big integer operation
        BigInteger x1y2 = (xOne.multiply(yTwo)).mod(p);
        BigInteger y1x2 = (yOne.multiply(xTwo)).mod(p);
        BigInteger x1x2 = (xOne.multiply(xTwo)).mod(p);
        BigInteger y1y2 = (yOne.multiply(yTwo)).mod(p);

        BigInteger x1x2y1y2 = (x1x2.multiply(y1y2)).mod(p);
        BigInteger dx1x2y1y2 = (d.multiply(x1x2y1y2)).mod(p);

        BigInteger xNum = (x1y2.add(y1x2)).mod(p);
        BigInteger xDen = (BigInteger.ONE.add(dx1x2y1y2)).mod(p);

        BigInteger yNum = (y1y2.subtract(x1x2)).mod(p);
        BigInteger yDen = (BigInteger.ONE.subtract(dx1x2y1y2)).mod(p);

        BigInteger xOut = (xNum.multiply(xDen.modInverse(p)));
        BigInteger yOut = (yNum.multiply(yDen.modInverse(p)));

        return new EllipticPoint(xOut.mod(p), yOut.mod(p));
    }

    /**
     * Scalar multiplication of scalar k against an EllipticPoint
     * @param k the scalar
     * @param pt a point
     * @return
     */
    /* Method inspired from pseudocode at
       https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
     */

    public static EllipticPoint scale(BigInteger k, EllipticPoint pt) {
        String bitK = k.toString(2);
        EllipticPoint result = new EllipticPoint();
        EllipticPoint addend = pt;
        for (int i = bitK.length() - 1; i >= 0; i--) {
            if (bitK.charAt(i) == '1') {
                result = result.sum(addend);
            }
            addend = addend.sum(addend);
        }
        return result;
    }
}
