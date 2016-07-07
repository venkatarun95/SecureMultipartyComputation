package pederson;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

public class PedersonShare {
		// Group over which we operate
		private static final BigInteger mod = new BigInteger("2698727"); //982451653");
		private static final BigInteger modQ = mod.subtract(BigInteger.ONE).divide(new BigInteger("2"));
		// Group generators
		static private BigInteger genData = new BigInteger("2");
		static private BigInteger genVerif = new BigInteger("4");

		// Value of data-containing polynomial at `index`
		private BigInteger valData;
		// Value of verifying zero polynomial at `index`
		private BigInteger valVerif;
		private BigInteger index;
		// Commitments to make sure sharing is valid
		private BigInteger[] commitments;
		// Number of shares required to reconstruct a secret
		private int threshold;

		private PedersonShare(BigInteger a_valData, BigInteger a_valVerif, BigInteger a_index, BigInteger[] a_commitments, int a_threshold) {
				valData = a_valData;
				valVerif = a_valVerif;
				index = a_index;
				commitments = a_commitments;
				threshold = a_threshold;
		}
		
		private void validate() throws CheatAttemptException {
				BigInteger mac = BigInteger.ONE;
				BigInteger exp = BigInteger.ONE;
				for (int i = 0; i < commitments.length; ++i) {
						mac = mac.multiply(commitments[i].modPow(exp, mod)).mod(mod);
						exp = exp.multiply(index);
				}
				BigInteger rhs = genData.modPow(valData, mod);
				rhs = rhs.multiply(genVerif.modPow(valVerif, mod)).mod(mod);
				if (mac.compareTo(rhs) != 0)
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

		public static PedersonShare[] shareValue(BigInteger val, int threshold, int numShares) {
				BigInteger[] polyData = new BigInteger[threshold];
				BigInteger[] polyVerif = new BigInteger[threshold];
				SecureRandom random = new SecureRandom();
				for (int i = 0; i < threshold; ++i) {
						polyData[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
						polyVerif[i] = BigIntegers.createRandomInRange(BigInteger.ZERO, modQ.subtract(BigInteger.ONE), random);
				}
				polyData[0] = val;

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
