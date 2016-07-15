package mpcCrypto;

import java.io.Serializable;
import java.math.BigInteger;
import pederson.PedersonShare;

/**
 * Represents share of a signature. Also contains shares of the
 * message that is signed.
 */
public class SchnorrSignatureShare implements Serializable {
		public PedersonShare publicKey;
		public PedersonShare message;
		BigInteger e;
		BigInteger s;
}
