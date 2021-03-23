package pederson;

import java.util.Arrays;
import java.util.HashMap;
import java.math.BigInteger;
import java.security.SecureRandom;

import matrix.Matrix;
import matrix.MatrixMathematics;
import matrix.NoSquareException;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import pederson.PedersonShare;

enum State {
    NOT_STARTED,
    POLY_SENT,
    ZKP_STEP1_DONE,
    ZKP_STEP2_DONE
}

/**
 * Class to keep track of state required during multiplication of two
 * Pedersen-shared values.<p>
 *
 * Helps PedersonComm in doing the multiplication by handling most of
 * the math.<p>
 *
 * For details about the algorithm refer to Appendix F in 'Gennaro,
 * Rosario, Michael O. Rabin, and Tal Rabin. "Simplified VSS and
 * fast-track multiparty computations with applications to threshold
 * cryptography." Proceedings of the seventeenth annual ACM symposium
 * on Principles of distributed computing. ACM, 1998.'
 */
public class PedersonMultiply {
    private int numShares, threshold;
    private PedersonShare[] shares;
    private State state;
    private SecureRandom random;

    private BigInteger d, s, x, s1, s2;
    private BigInteger alpha, rho, beta, sigma;
    //private BigInteger A, B;
    private PedersonShare aShare, bShare;

    /**
     * Cached inverses of Van der Monde matrices
     */
    private static HashMap<Integer, Matrix> vandermondeInv = new HashMap<Integer, Matrix>();

    public PedersonMultiply() {
        state = State.NOT_STARTED;
        random = new SecureRandom();
    }

    /**
     * Returns (y, x)^th cell of the first row of the Van der Monde
     * matrix.<p>
     */
    static BigInteger getVandermondeInv(int y, int x, int n) {
        Matrix inverse = vandermondeInv.get(n);
        if (inverse == null) {
            // Compute the inverse now
            double[][] mat = new double[n][n];
            for (int i = 0; i < n; ++i)
                for (int j = 0; j < n; ++j)
                    mat[i][j] = Math.pow(i + 1, j);
            try {
                inverse = MatrixMathematics.inverse(new Matrix(mat));
            }
            catch (NoSquareException e) {
                throw new RuntimeException("Programming error: Generated matrix is not square.");
            }
						// Cache the inverse matrix
            vandermondeInv.put(n, inverse);
        }
        return BigInteger.valueOf((long)Math.round(inverse.getValueAt(x-1, y-1)));
    }

    /**
     * Generates polynomial that this player must share with others to
     * multiply values of the shares <code>a</code> and <code>b</code>
     */
    public PedersonShare[] sharedPoly(PedersonShare a, PedersonShare b, int a_numShares) {
        assert state == State.NOT_STARTED;
        assert a.index == b.index;
        numShares = a_numShares;

        if (a.threshold != b.threshold)
            throw new RuntimeException("The thresholds for the two values to be multiplied are not the same.");
        BigInteger lambda = getVandermondeInv((int)a.index.longValue(), 1, numShares);

        shares = PedersonShare.shareValue(a.valData.multiply(b.valData).mod(PedersonShare.modQ),
                                          a.threshold,
                                          numShares);

        alpha = a.valData;
        rho = a.valVerif;
        beta = b.valData;
        sigma = b.valVerif;
        aShare = a;
        bShare = b;
        threshold = a.threshold;

        state = State.POLY_SENT;
        return shares;
    }

    /**
     * Produces random commitments that must be given to verifiers (if
     * this player is the prover).<p>
     *
     * To tolerate malicious verifiers, the verifies must have
     * commited to a random challenge.
     */
    public Element[] zkpProverStep1() {
        assert state == State.POLY_SENT;
        int numBits = PedersonShare.modQ.bitLength();
        d = new BigInteger(numBits, random).mod(PedersonShare.modQ);
        s = new BigInteger(numBits, random).mod(PedersonShare.modQ);
        x = new BigInteger(numBits, random).mod(PedersonShare.modQ);
        s1 = new BigInteger(numBits, random).mod(PedersonShare.modQ);
        s2 = new BigInteger(numBits, random).mod(PedersonShare.modQ);

        Element[] result = new Element[3];
        result[0] = PedersonShare.genData_pp.pow(d).
            mul(PedersonShare.genVerif_pp.pow(s));
        result[1] = PedersonShare.genData_pp.pow(x).
            mul(PedersonShare.genVerif_pp.pow(s1));
        result[2] = bShare.computeMac(bShare.index).pow(x).
            mul(PedersonShare.genVerif_pp.pow(s2));

        state = State.ZKP_STEP1_DONE;
        return result;
    }

    /**
     * Given a random challenge <code>e</code> in
     * Z_{<code>PedersonShare.modQ</code>} produces a Zero Knowledge
     * Proof that the shared polynomial is correct according to
     * previous commitments.
     */
    public BigInteger[] zkpProverStep2(BigInteger e) {
        assert state == State.ZKP_STEP1_DONE;
        BigInteger[] result = new BigInteger[5];

        // Reconstruct tau. We could have taken it while constructing
        // the shares, but this is more modular.
        BigInteger tau = BigInteger.ZERO;
        BigInteger modQ = PedersonShare.modQ;
        for (int i = 0; i < threshold; ++i) {
            BigInteger coeff = BigInteger.ONE;
            for (int j = 0; j < threshold; ++j) {
                if (i == j)
                    continue;
                coeff = coeff.multiply(shares[j].index).mod(modQ);
                BigInteger denom = shares[j].index.subtract(shares[i].index).mod(modQ).modInverse(modQ);
                coeff = coeff.multiply(denom).mod(modQ);
            }
            tau = tau.add(coeff.multiply(shares[i].valVerif)).mod(modQ);
        }

        result[0] = d. add(e.multiply(beta)). mod(modQ);
        result[1] = s. add(e.multiply(sigma)).mod(modQ);
        result[2] = x. add(e.multiply(alpha)).mod(modQ);
        result[3] = s1.add(e.multiply(rho)).  mod(modQ);
        result[4] = s2.add(e.multiply(tau.subtract(sigma.multiply(alpha)
                                                   .mod(modQ))
                                      ).mod(modQ)).mod(modQ);

        state = State.ZKP_STEP2_DONE;
        return result;
    }

    /**
     * Verifies that the zero knowledge proof given by prover is correct.
     *
     * @param otherIndex Index of prover (according to value stored in
     * PedersonShare that is given to them).
     * @param share Share given by prover (whose validity is being
     * proven) to this player.
     * @param commitments Commitments given by prover possibly
     * produced using zkpProverStep1 @see
     * pederson.PedersonMultiply.zkpProverStep1
     * @param challenge Random challenge number given to prover
     * @param response Response produced by prover to random challenge
     * possubly using zkpProverStep2 @see
     * pederson.PedersonMultiply.zkpProverStep2
     */
    public boolean verifyProof(int otherIndex, PedersonShare share, Element[] commitments, BigInteger challenge, BigInteger[] response) {
        Element A = aShare.computeMac(BigInteger.valueOf(otherIndex));
        Element B = bShare.computeMac(BigInteger.valueOf(otherIndex));
        Element C = share.commitments[0];// share.computeMac(BigInteger.valueOf(otherIndex));
        ElementPowPreProcessing genData_pp = PedersonShare.genData_pp, genVerif_pp = PedersonShare.genVerif_pp;

        Element check1Lhs = genData_pp.pow(response[0]).
            mul(genVerif_pp.pow(response[1]));
        Element check1Rhs = commitments[0].duplicate().mul(B.duplicate().pow(challenge));
        if (!check1Lhs.isEqual(check1Rhs))
            return false;

        Element check2Lhs = genData_pp.pow(response[2]).
            mul(genVerif_pp.pow(response[3]));
        Element check2Rhs = commitments[1].duplicate().mul(A.duplicate().pow(challenge));
        if (!check2Lhs.isEqual(check2Rhs))
            return false;

        Element check3Lhs = B.duplicate().pow(response[2]).
						mul(genVerif_pp.pow(response[4]));
        Element check3Rhs = commitments[2].duplicate().mul(C.duplicate().pow(challenge));
        if (!check3Lhs.isEqual(check3Rhs))
            return false;
        return true;
    }
}
