package pederson;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

public class PedersonShare implements Serializable {
		// Group over which we operate
		public static final BigInteger mod = new BigInteger("2698727"); //982451653");
		public static final BigInteger modQ = mod.subtract(BigInteger.ONE).divide(new BigInteger("2"));
		// Group generators
		public static BigInteger genData = new BigInteger("2");
		public static BigInteger genVerif = new BigInteger("4");

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
		BigInteger[] commitments;
		// Number of shares required to reconstruct a secret
		int threshold;

		// Copy constructor
		private PedersonShare(BigInteger a_valData, BigInteger a_valVerif, BigInteger a_index, BigInteger[] a_commitments, int a_threshold) {
				valData = a_valData;
				valVerif = a_valVerif;
				index = a_index;
				commitments = Arrays.copyOf(a_commitments, a_commitments.length);
				threshold = a_threshold;
		}

		BigInteger computeMac(BigInteger indexAt) {
				BigInteger mac = BigInteger.ONE;
				BigInteger exp = BigInteger.ONE;
				for (int i = 0; i < commitments.length; ++i) {
						mac = mac.multiply(commitments[i].modPow(exp, mod)).mod(mod);
						exp = exp.multiply(indexAt);
				}
				return mac;
		}
		
		void validate() throws CheatAttemptException {				
				BigInteger rhs = genData.modPow(valData, mod);
				rhs = rhs.multiply(genVerif.modPow(valVerif, mod)).mod(mod);
				if (computeMac(index).compareTo(rhs) != 0)
						throw new CheatAttemptException("The commitments do not match the given values!");
		}

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
						result.commitments[i] = result.commitments[i].multiply(other.commitments[i]);
				return result;
		}

		public PedersonShare constMultiply(BigInteger c) {
				PedersonShare result = new PedersonShare(valData.multiply(c).mod(modQ),
																								 valVerif.multiply(c).mod(modQ),
																								 index,
																								 commitments,
																								 threshold);
				for (int i = 0; i < commitments.length; ++i)
						result.commitments[i] = result.commitments[i].modPow(c, mod);
				return result;
		}

		static boolean verifyCommitmentEquality(PedersonShare[] shares) {
				assert shares != null && shares.length > 0;
				BigInteger[] commitments = shares[0].commitments;
				for (int i = 1; i < commitments.length; ++i) {
						if (commitments.length != shares[i].commitments.length)
								return false;
						for (int j = 0; j < commitments.length; ++j)
								if (commitments[j].compareTo(shares[i].commitments[j]) != 0)
										return false;
				}
				return true;
		}
		
		public static PedersonShare[] shareValue(BigInteger val, int threshold, int numShares) {
				BigInteger[] polyData = new BigInteger[threshold];
				BigInteger[] polyVerif = new BigInteger[threshold];
				SecureRandom random = new SecureRandom();
				for (int i = 0; i < threshold; ++i) {
						polyData[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
						polyVerif[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
				}
				polyData[0] = val.mod(modQ);
				System.out.println("Creation Tau: " + polyVerif[0]);

				BigInteger[] commitments = new BigInteger[threshold];
				for (int i = 0; i < threshold; ++i) {
						commitments[i] = genData.modPow(polyData[i], mod).
								multiply(genVerif.modPow(polyVerif[i], mod)).mod(mod);
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
		
		public static BigInteger combineShares(PedersonShare[] shares) {
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
}
