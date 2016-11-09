package pederson;

import java.io.Serializable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.lang.management.ManagementFactory;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class PedersonShare implements Serializable {
    // Group over which we operate
		public static Pairing pairing = PairingFactory.getPairing("a.properties");
		public static Field group = pairing.getG1();
    // public static final BigInteger mod = new BigInteger("2698727"); //982451653");
		public static final BigInteger modQ = group.getOrder(); //mod.subtract(BigInteger.ONE).divide(new BigInteger("2"));
		
    // Group generators
    // public static BigInteger genData = new BigInteger("2");
    // public static BigInteger genVerif = new BigInteger("4");
		static public Element genData = group.newElementFromHash(new byte[] {(byte)0x3f, (byte)0x84, (byte)0x8d, (byte)0x67}, 0, 4);
		static public Element genVerif = group.newElementFromHash(new byte[] {(byte)0x02, (byte)0xf6, (byte)0x19, (byte)0x3b}, 0, 4); 
		public static ElementPowPreProcessing genData_pp = genData.getElementPowPreProcessing();
		public static ElementPowPreProcessing genVerif_pp = genVerif.getElementPowPreProcessing();

    // Note: `PedersonMultiply` needs to access `valData`, `valVerif`
    // and `threshold`, so we give access to there within this
    // (pederson) package.
    //
    // @see pederson.PedersonComm needs commitments (to verify they
    // are all the same)

    // Value of data-containing polynomial at `index`
    BigInteger valData;
    // Value of verifying zero polynomial at `index`
    BigInteger valVerif;
    BigInteger index;
    // Commitments to make sure sharing is valid
    Element[] commitments;
    // Number of shares required to reconstruct a secret
    public int threshold;

    // Copy constructor
    private PedersonShare(BigInteger a_valData, BigInteger a_valVerif, BigInteger a_index, Element[] a_commitments, int a_threshold) {
        valData = a_valData;
        valVerif = a_valVerif;
        index = a_index;
				commitments = new Element[a_commitments.length];
				for (int i = 0; i < commitments.length; ++i)
						commitments[i] = a_commitments[i].duplicate();
        threshold = a_threshold;
    }

    /**
     * Computes MAC at a given index using commitments.<p>
     *
     * If the polynomials represented by this share are f(x), f'(x),
     * returns g^f(indexAt) * h^f'(indexAt) where g =
     * <code>genData</code> and h = <code>genVerif</code>.
     */
    Element computeMac(BigInteger indexAt) {
        Element mac = group.newElement(1);
        BigInteger exp = BigInteger.valueOf(1);
        for (int i = 0; i < commitments.length; ++i) {
						Element commitment = commitments[i].duplicate();
            mac.mul(commitment.pow(exp));
            exp = exp.multiply(indexAt);
        }
        return mac;
    }

    /**
     * Verifies the MAC values.
     */
    void validate() throws CheatAttemptException {
        Element rhs = genData_pp.pow(valData);
        rhs = rhs.mul(genVerif_pp.pow(valVerif));
        if (!computeMac(index).isEqual(rhs))
            throw new CheatAttemptException("The commitments do not match the given values!");
    }

    /**
     * Evaluates given polynomial at given point in field Z_{modQ}.
     *
     * @param poly i^th elements contains coefficient of x^i of
     * polynomial.
     */
    private static BigInteger evaluatePolynomial(BigInteger[] poly, int a_point) {
        BigInteger point = BigInteger.valueOf(a_point);
        BigInteger result = BigInteger.ZERO;
        BigInteger mul = BigInteger.ONE;
        for (BigInteger coeff : poly) {
            result = result.add(coeff.multiply(mul).mod(modQ)).mod(modQ);
            mul = mul.multiply(point);
        }
        return result;
    }

    /**
     * Returns share of a value that is the sum of this share's value
     * and value of share given in the argument.
     */
    public PedersonShare add(PedersonShare other) {
        if (index.compareTo(other.index) != 0)
            throw new RuntimeException("Can only add shares if they have the same index. Here we have " + index + ", " + other.index);
        if (threshold != other.threshold)
            throw new RuntimeException("Thresholds for the two shares are different. They may belong to different polynomials.");
        PedersonShare result = new PedersonShare(valData.add(other.valData).mod(modQ),
                                                 valVerif.add(other.valVerif).mod(modQ),
                                                 index,
                                                 commitments,
                                                 threshold);
        for (int i = 0; i < commitments.length; ++i)
            result.commitments[i] = result.commitments[i].mul(other.commitments[i]);
        return result;
    }

    /**
     * Returns share of a value that is a constant (<code>c</code>)
     * times the value of this share.
     */
    public PedersonShare constMultiply(BigInteger c) {
				c = c.mod(modQ);
        PedersonShare result = new PedersonShare(valData.multiply(c).mod(modQ),
                                                 valVerif.multiply(c).mod(modQ),
                                                 index,
                                                 commitments,
                                                 threshold);
        for (int i = 0; i < commitments.length; ++i)
            result.commitments[i].pow(c);
        return result;
    }

    /**
     * Verifies that the public commitment stored in all these shares
     * is the same.
     */
    static boolean verifyCommitmentEquality(PedersonShare[] shares) {
        assert shares != null && shares.length > 0;
        Element[] commitments = shares[0].commitments;
        for (int i = 1; i < commitments.length; ++i) {
            if (commitments.length != shares[i].commitments.length)
                return false;
            for (int j = 0; j < commitments.length; ++j) {
                if (!commitments[j].isEqual(shares[i].commitments[j]))
                    return false;
						}
        }
				return true;
    }

    /**
     * Returns <code>numShares</code> shares of the number
     * <code>val</code> such that anybody with <code>threshold</code>
     * number of these shares can find <code>val</code>. Anybody with
     * fewer shares cannot find the value, even if they are
     * computationally unbounded.<p>
     *
     * <code>val</code> is assumed to be a number in Z_q (ie. an
     * integer between <code>0</code> and <code>PedersonShare.modQ -
     * 1</code>)
     */
    public static PedersonShare[] shareValue(BigInteger val, int threshold, int numShares) {
        BigInteger[] polyData = new BigInteger[threshold];
        BigInteger[] polyVerif = new BigInteger[threshold];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < threshold; ++i) {
            polyData[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
            polyVerif[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
        }
        polyData[0] = val.mod(modQ);

        Element[] commitments = new Element[threshold];
        for (int i = 0; i < threshold; ++i) {
            commitments[i] = genData_pp.pow(polyData[i]).
                mul(genVerif_pp.pow(polyVerif[i]));
        }

        PedersonShare[] result = new PedersonShare[numShares];
        for (int i = 1; i < numShares + 1; ++i) {
            result[i-1] = new PedersonShare(evaluatePolynomial(polyData, i),
                                            evaluatePolynomial(polyVerif, i),
                                            BigInteger.valueOf(i),
                                            commitments,
                                            threshold);
        }
        return result;
    }

    /**
     * Returns <code>numShares</code> shares of a public constant
     * <code>val</code> threshold <code>threshold</code>. All shares
     * are known to everybody.
     *
     * <code>val</code> is assumed to be a number in Z_q (ie. an
     * integer between <code>0</code> and <code>PedersonShare.modQ</code>
     */
    public static PedersonShare[] shareConstValue(BigInteger val, int threshold, int numShares) {
        BigInteger[] polyData = new BigInteger[threshold];
        BigInteger[] polyVerif = new BigInteger[threshold];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < threshold; ++i) {
            polyData[i] = BigInteger.valueOf(i);
            polyVerif[i] = BigInteger.valueOf(i);
        }
        polyData[0] = val.mod(modQ);

        Element[] commitments = new Element[threshold];
        for (int i = 0; i < threshold; ++i) {
            commitments[i] = genData_pp.pow(polyData[i]).
                mul(genVerif_pp.pow(polyVerif[i]));
        }

        PedersonShare[] result = new PedersonShare[numShares];
        for (int i = 1; i < numShares + 1; ++i) {
            result[i-1] = new PedersonShare(evaluatePolynomial(polyData, i),
                                            evaluatePolynomial(polyVerif, i),
                                            BigInteger.valueOf(i),
                                            commitments,
                                            threshold);
        }
        return result;
    }

    /**
     * If there are enough number of the shares (as indicated by their
     * <code>threshold</code> property), returns the value they
     * represent.
     *
     * @throws CheatAttemptException If the MAC values on the shares
     * don't check out.
     * @throws RuntimeException If indufficient number of shares are
     * given or <code>threshold</code> value in all shares is not the
     * same.
     */
    public static BigInteger combineShares(PedersonShare[] shares) throws CheatAttemptException {
        // Run some checks
        if (shares == null || shares.length == 0)
            throw new RuntimeException("No shares given. Cannot reconstruct.");
        int threshold = shares[0].threshold;
        for (PedersonShare share : shares)
            if (share.threshold != threshold)
                throw new RuntimeException("Thresholds for all shares are not the same.");
        if (shares.length < threshold)
            throw new RuntimeException("Insufficient number of shares to reconstruct secret.");
        // Verify all available shares, because it doesn't hurt.
        for (PedersonShare share : shares)
            share.validate();

        //TODO(venkat): Verify that commitments in all shares are the same

        // Reconstruct value using just the first `threshold` shares
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < threshold; ++i) {
            BigInteger coeff = BigInteger.ONE;
            for (int j = 0; j < threshold; ++j) {
                if (i == j)
                    continue;
                coeff = coeff.multiply(shares[j].index).mod(modQ);
                BigInteger denom = shares[j].index.subtract(shares[i].index).mod(modQ).modInverse(modQ);
                coeff = coeff.multiply(denom).mod(modQ);
            }
            result = result.add(coeff.multiply(shares[i].valData)).mod(modQ);
        }
        return result;
    }

		/**
		 * Write custom serialization method so we can handle
		 * <code>Element</code> which does not implement
		 * <code>Serializable</code>.
		 *
		 * Remember to update any new class members here.
		 */
		private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
				stream.writeObject(valData);
				stream.writeObject(valVerif);
				stream.writeObject(index);
				byte[][] commitments_bytes = new byte[commitments.length][];
				for (int i = 0; i < commitments.length; ++i)
						commitments_bytes[i] = commitments[i].toBytes();
				stream.writeObject(commitments_bytes);
				stream.writeInt(threshold);
		}

		private void readObject(java.io.ObjectInputStream stream) throws IOException, ClassNotFoundException {
				valData = (BigInteger) stream.readObject();
				valVerif = (BigInteger) stream.readObject();
				index = (BigInteger) stream.readObject();
				byte[][] commitments_bytes = (byte[][])stream.readObject();
				commitments = new Element[commitments_bytes.length];
				for (int i = 0; i < commitments.length; ++i) {
						commitments[i] = group.newElementFromBytes(commitments_bytes[i]);
				}
				threshold = stream.readInt();
		}
}
