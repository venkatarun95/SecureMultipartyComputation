//package test;

import java.math.BigInteger;
import java.util.Random;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import pederson.PedersonShare;

public class PedersonShareTest extends junit.framework.TestCase {
		@Test
		public void testSharedSecretShouldReconstruct() {
				PedersonShare[] shares = PedersonShare.shareValue(BigInteger.valueOf(15), 5, 10);
				assertEquals("There must be numShares shares", 10, shares.length);
				BigInteger reconstructed = PedersonShare.combineShares(shares);
				assertEquals("Reconstruction must be correct", 15, reconstructed.longValue());
		}

		@Test
		public void testRandomPoints() {
				int numShares = 10;
				int numVals = 100; // Should be even
				Random rand = new Random();
				for (int threshold : new int[] {1, 5, 10}) {
						// Construct sharings of lots of numbers
						ArrayList<BigInteger> vals = new ArrayList();
						ArrayList<PedersonShare[]> shares = new ArrayList();
						for (int i = 0; i < numVals/2; ++i) {
								BigInteger val = BigInteger.valueOf(rand.nextInt(PedersonShare.modQ.intValue()));
								vals.add(val);
								shares.add(PedersonShare.shareValue(val, threshold, numShares));
						}

						// Do linear combinations of these numbers
						for (int i = numVals / 2; i < numVals; ++i) {
								int a = rand.nextInt(i);
								int b = rand.nextInt(i);
								BigInteger alpha = BigInteger.valueOf(rand.nextInt(PedersonShare.modQ.intValue()));
								BigInteger beta = BigInteger.valueOf(rand.nextInt(PedersonShare.modQ.intValue()));
								vals.add((vals.get(a).multiply(alpha).add(vals.get(b).multiply(beta))).mod(PedersonShare.modQ));
								PedersonShare[] comb = new PedersonShare[numShares];
								for (int j = 0; j < numShares; ++j)
										comb[j] = shares.get(a)[j].constMultiply(alpha).add(shares.get(b)[j].constMultiply(beta));
								shares.add(comb);
						}

						// Verify if reconstruction is the same as what is expected
						for (int i = 0; i < numVals; ++i) {
								BigInteger reconstructed = PedersonShare.combineShares(shares.get(i));
								assertEquals("Incorrect reconstruction at index " + i, vals.get(i), reconstructed);
						}
				}
		}
}

