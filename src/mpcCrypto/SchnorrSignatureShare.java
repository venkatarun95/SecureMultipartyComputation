package mpcCrypto;

import java.io.Serializable;
import java.math.BigInteger;
import pederson.PedersonShare;

/**
 * Represents share of a signature. Also contains shares of the
 * message that is signed.
 */
public class SchnorrSignatureShare implements Serializable {
    // If true, publicKeyPt should be null otherwise publicKey should
    // be.
    public boolean publicKeyHidden;
    public PedersonShare publicKey;
    public BigInteger publicKeyPt;
    public PedersonShare message;
    BigInteger e;
    // Bitwise shared
    PedersonShare[] s;
}
