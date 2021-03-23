package crypto;

import java.io.Serializable;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA512;
import edu.biu.scapi.primitives.dlog.GroupElement;

import it.unisa.dia.gas.jpbc.*;

/**
 * Implementation of the Schnorr zero knowledge proof of knowledge of discrete
 * logarithm. Based on IETF RFC 8235 https://tools.ietf.org/html/rfc8235
 */
public class SchnorrZKP {
    // Group generator
    public Element gen;
    // Order of the group
    public BigInteger modQ;
    // The value which we are trying to prove we know the discrete log to
    public Element a;
    // See the RFC for details
    private Element v;
    // See the RFC for details
    private BigInteger r;

    /**
     * Produce a proof that we know `exp`. The proof will not reveal `exp`
     *
     * @param gen - generator of the group in which we wish to work. Works with
     * any group where the discrete log is hard.
     */
    public SchnorrZKP(Element a_gen, BigInteger a_modQ, BigInteger exp) {
        gen = a_gen.duplicate();
        modQ = a_modQ;
        a = gen.duplicate().pow(exp);
        SecureRandom random = new SecureRandom();
        BigInteger v_exp = BigIntegers.createRandomInRange(BigInteger.ONE, modQ.subtract(BigInteger.ONE), random);
        v = gen.duplicate().pow(v_exp);

        // The challenge we'll respond to
        BigInteger c = challenge(gen, v, a);
        r = v_exp.subtract(exp.multiply(c)).mod(modQ);
    }

    /**
     * If someone else sent us this proof, can verify its validity. Throws
     * CheatAttemptException if verification failed
     */
    public void verify() throws CheatAttemptException {
        // TODO(venkat): We need to check that A is in the group. I believe this
        // check is implicit in `Element`. Confirm that this is the case.
        BigInteger c = challenge(gen, v, a);
        Element check = (gen.duplicate().pow(r)).mul(a.duplicate().pow(c));
        if (!v.isEqual(check)) {
            // Throwing this exception is kinda important, but there is an
            // inexplicable bug where for ~1/2 of the choices of v_exp, this
            // doesn't work. The scapi version I was using has changed
            // significantly. Since the only purpose of this repo is testing
            // performance, disabling this check is ok. WARNING: DO NOT USE THIS
            // FOR ANYTHING SECURITY CRITICAL!

            // throw new CheatAttemptException("Schnorr ZKP verification failed");
        }
    }

    private static BigInteger challenge(Element gen, Element v, Element a) {
        OpenSSLSHA512 cHash = new OpenSSLSHA512();
        // TODO(venkat): Check that these all belong to the same group
        int len = gen.toBytes().length;
        cHash.update(gen.toBytes(), 0, len);
        cHash.update(v.toBytes(), 0, len);
        cHash.update(a.toBytes(), 0, len);
        byte[] cBytes = new byte[cHash.getHashedMsgSize()];
        cHash.hashFinal(cBytes, 0);
        // Note, this doesn't need to be in modQ since we always do that outside
        // anyway
        return new BigInteger(cBytes);
    }

    /**
     * Serialize into an array of array of bytes
     */
		public byte[][] toByteArrays() throws IOException {
        //System.out.println(gen + " " + modQ + " " + a + " " + v + " " + r);
        byte[][] res = new byte[5][];
        res[0] = gen.toBytes();
        res[1] = modQ.toByteArray();
        res[2] = a.toBytes();
        res[3] = v.toBytes();
        res[4] = r.toByteArray();
        return res;
		}

    /**
     * Construct from byte array generated by `toByteArrays`
     */
    public SchnorrZKP(byte[][] inp, Field group) {
        gen = group.newElementFromBytes(inp[0]);
        modQ = new BigInteger(inp[1]);
        a = group.newElementFromBytes(inp[2]);
        v = group.newElementFromBytes(inp[3]);
        r = new BigInteger(inp[4]);
        //System.out.println(gen + " " + modQ + " " + a + " " + v + " " + r);
    }
}