package pederson;

import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;

public class PedersonShare {
		// Group over which we operate
		static private DlogGroup group;
		// Corresponding group generators
		static private GroupElement genData;
		static private GroupElement genVerif;

		// Value of data-containing polynomial at `index`
		private GroupElement valData;
		// Value of verifying zero polynomial at `index`
		private GroupElement valVerif;
		private BigInteger index;
		// Commitments to make sure sharing is valid
		private GroupElement[] commitments;
		
		private void validate() throws CheatAttemptException {
				GroupElement mac = group.getIdentity();
				BigInteger exp = BigInteger.valueOf(1);
				for (int i = 0; i < commitments.length; ++i) {
						mac = group.multiplyGroupElements(mac,
																							group.exponentiate(commitments[i], exp));
						exp = exp.multiply(index);
				}
				GroupElement rhs = group.exponentiate(genData, index);
				rhs = group.multiplyGroupElements(rhs,
																					group.exponentiate(genVerif, index));
				if (mac != rhs)
						throw new CheatAttemptException("The commitments do not match the given values!");
		}

		public static PedersonShare[] shareValues(GroupElement val, int threshold, int numShares) {
				GroupElement[] polyData = new GroupElement[threshold];
				GroupElement[] polyVerif = new GroupElement[threshold];
				for (int i = 0; i < threshold; ++i) {
						polyData = group.createRandomElement();
						polyVerif = group.createRandomElement();
				}
				polyData[0] = val;
		}
}
