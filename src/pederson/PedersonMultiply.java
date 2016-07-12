package pederson;

import java.util.HashMap;
import java.math.BigInteger;
import java.security.SecureRandom;

import matrix.Matrix;
import matrix.MatrixMathematics;
import matrix.NoSquareException;

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
 * Helps PedersonComm in doing the multiplication.<p>
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
		private BigInteger alpha, rho, beta, sigma, tau;
		private BigInteger A, B;
		//private PedersonShare aShare, bShare;

		/**
		 * Cached inverses of Van der Monde matrices
		 */
		private static HashMap<Integer, Matrix> vandermondeInv = new HashMap<Integer, Matrix>();

		public PedersonMultiply() {
				state = State.NOT_STARTED;
				random = new SecureRandom();
		}

		/**
		 * For use by getVandermondeInv
		 */
		private static BigInteger combinationProduct(BigInteger[] nos, int n, int len, int startPosition){
        if (len == 0)
            return BigInteger.ONE;
				BigInteger sum = BigInteger.ZERO;
        for (int i = startPosition; i < n-len; i++) {
            sum = sum.add(nos[i].
													multiply(combinationProduct(nos, n, len-1, i+1)));
        }
				System.out.print("combPStatus: [");
				for (BigInteger no : nos) System.out.print(no + " ");
				System.out.print("] " + n + " " + len + " " + startPosition + " = " + sum);
				return sum;
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
						vandermondeInv.put(n, inverse);
				}
				return BigInteger.valueOf((long)Math.round(inverse.getValueAt(x-1, y-1)));

				// BigInteger[] nos = new BigInteger[n - 1];
				// int curNo = 1;
				// for (int i = 0; i < n - 1; ++i) {
				// 		if (curNo == y)
				// 				++curNo;
				// 		nos[i] = BigInteger.valueOf(curNo);
				// 		System.out.print(curNo + ":" + y + " ");
				// 		++curNo;
				// }
				// System.out.println(" <- nos");
				// BigInteger numerator = combinationProduct(nos, n, n - x, 0);
				// if (x % 2 == 0)
				// 		numerator = PedersonShare.modQ.subtract(numerator);

				// BigInteger numerator = BigInteger.ONE;
				// int curNo = 1;
				// for (int i = 0; i < n - 1; ++i) {
				// 		if (curNo == y)
				// 				++curNo;
				// 		numerator = numerator.multiply(BigInteger.valueOf(curNo));
				// 		++curNo;
				// }
				
				// BigInteger denominator = BigInteger.valueOf(y);
				// System.out.println("combP: " + y + " " + numerator);
				// for (int i = 1; i <= n; ++i) {
				// 		if (i == y)
				// 				continue;
				// 		denominator = denominator.multiply(BigInteger.valueOf(i - y));
				// }
				// return numerator.multiply(denominator.modInverse(PedersonShare.modQ)).mod(PedersonShare.modQ);
		}

		public PedersonShare[] sharedPoly(PedersonShare a, PedersonShare b, int a_numShares) {
				assert state == State.NOT_STARTED;
				assert a.index == b.index;
				numShares = a_numShares;

				if (a.threshold != b.threshold)
						throw new RuntimeException("The thresholds for the two values to be multiplied are not the same.");
				BigInteger lambda = getVandermondeInv((int)a.index.longValue(), 1, numShares);

				shares = PedersonShare.shareValue((a.valData.multiply(b.valData).mod(PedersonShare.modQ)).multiply(lambda).mod(PedersonShare.modQ),
																					a.threshold,
																					numShares);
				System.out.println("To share: " + PedersonShare.combineShares(shares) + " " + a.index + " " + a.valData + " "+ b.valData + " " + lambda);

				alpha = a.valData;
				rho = a.valVerif;
				beta = b.valData;
				sigma = b.valVerif;
				A = a.commitments[0];
				B = b.commitments[0];
				
				state = State.POLY_SENT;
				return shares;
		}

		public BigInteger[] zkpProverStep1() {
				assert state == State.POLY_SENT;
				int numBits = PedersonShare.modQ.bitLength();
				d = new BigInteger(numBits, random).mod(PedersonShare.modQ);
				s = new BigInteger(numBits, random).mod(PedersonShare.modQ);
				x = new BigInteger(numBits, random).mod(PedersonShare.modQ);
				s1 = new BigInteger(numBits, random).mod(PedersonShare.modQ);
				s2 = new BigInteger(numBits, random).mod(PedersonShare.modQ);

				BigInteger[] result = new BigInteger[3];
				result[0] = PedersonShare.genData.modPow(d, PedersonShare.mod).
						multiply(PedersonShare.genVerif.modPow(s, PedersonShare.mod)).
						mod(PedersonShare.mod);
				result[1] = PedersonShare.genData.modPow(x, PedersonShare.mod).
						multiply(PedersonShare.genVerif.modPow(s1, PedersonShare.mod)).
						mod(PedersonShare.mod);
				result[2] = B.modPow(x, PedersonShare.mod).
						multiply(PedersonShare.genVerif.modPow(s2, PedersonShare.mod)).
						mod(PedersonShare.mod);

				state = State.ZKP_STEP1_DONE;
				return result;
		}

		public BigInteger[] zkpProverStep2(BigInteger e) {
				assert state == State.ZKP_STEP1_DONE;
				BigInteger[] result = new BigInteger[5];

				// Reconstruct tau. We could have taken it while constructing
				// the shares, but this is more modular.
				BigInteger tau = BigInteger.ZERO, modQ = PedersonShare.modQ;
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
						
				result[0] = d. add(e.multiply(beta)). mod(PedersonShare.modQ);
				result[1] = s. add(e.multiply(sigma)).mod(PedersonShare.modQ);
				result[2] = x. add(e.multiply(alpha)).mod(PedersonShare.modQ);
				result[3] = s1.add(e.multiply(rho)).  mod(PedersonShare.modQ);				
				result[4] = s2.add(e.multiply(tau)).  mod(PedersonShare.modQ);

				state = State.ZKP_STEP2_DONE;
				return result;
		}

		public boolean verifyProof(PedersonShare share, BigInteger[] commitments, BigInteger challenge, BigInteger[] response) {
				//BigInteger A = 
				BigInteger C = share.computeMac();
				BigInteger mod = PedersonShare.mod;
				BigInteger genData = PedersonShare.genData, genVerif = PedersonShare.genVerif;
				
				BigInteger check1Lhs = genData.modPow(response[0], mod).
						multiply(genVerif.modPow(response[1], mod)).mod(mod);
				BigInteger check1Rhs = commitments[0].multiply(B.modPow(challenge, mod)).mod(mod);
				System.out.println("Check1 " + check1Lhs + " " + check1Rhs);
				if (check1Lhs.compareTo(check1Rhs) != 0)
						return false;
				System.out.println("Check 1 passed");

				BigInteger check2Lhs = genData.modPow(response[2], mod).
						multiply(genVerif.modPow(response[3], mod)).mod(mod);
				BigInteger check2Rhs = commitments[1].multiply(A.modPow(challenge, mod));
				if (check2Lhs.compareTo(check2Rhs) != 0)
						return false;
				System.out.println("Check 2 passed");

				BigInteger check3Lhs = B.modPow(response[2], mod).
						multiply(genVerif.modPow(response[4], mod)).mod(mod);
				BigInteger check3Rhs = commitments[2].multiply(C.modPow(challenge, mod));
				if (check3Lhs.compareTo(check3Rhs) != 0)
						return false;
				System.out.println("Check 3 passed");
				
				return true;
		}
}
