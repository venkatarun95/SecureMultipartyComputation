package mpcCrypto;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import pederson.PedersonShare;
import pederson.PedersonComm;

/**
 * Class for VPRF (verifiable pseudo-random function) computation in a
 * multi-party setting. Needs <code>PedersonShare</code> to use a group that
 * satisfies the q-DBDHI (q-Decisional Bilinear Diffie Hellman Inversion)
 * assumption.
 */
public class PRF implements Serializable {
		PedersonShare key;
    // For verifying the VPRF
    Element publicKey;
		int threshold;

		public PRF(int a_threshold, Channel[] channels) throws IOException {
				threshold = a_threshold;
				key = PedersonComm.shareRandomNumber(threshold, channels);
        publicKey = PedersonComm.plaintextBilinearExponentiate(key, channels);
		}

		/**
		 * Reveals the secret key for this PRF in plaintext.
		 *
		 * Use very carefully. Revealing key will compromize all values
		 * whose PRF has been computed.
		 */
		public BigInteger revealKey(Channel[] channels) throws IOException {
				return PedersonComm.combineShares(key, channels);
		}

    private PedersonShare computeExponent(PedersonShare val, Channel[] channels) throws IOException {
        PedersonShare toInvert = key.add(val);
				PedersonShare blind = PedersonComm.shareRandomNumber(threshold, channels);
				PedersonShare blinded = PedersonComm.multiply(toInvert, blind, channels);
				BigInteger revealed = PedersonComm.combineShares(blinded, channels);
				BigInteger blindInverted = revealed.modInverse(PedersonShare.modQ);
				PedersonShare revealedShare = PedersonShare.shareConstValue(blindInverted, threshold, channels.length)[val.getIndex()-1];
				PedersonShare inverted = PedersonComm.multiply(revealedShare, blind, channels);
        return inverted;
    }

		/**
		 * Compute the PRF of the given secret shared value.
		 */
		public Element compute(PedersonShare val, Channel[] channels) throws IOException {
				PedersonShare inverted = computeExponent(val, channels);
				return PedersonComm.plaintextBilinearExponentiate(inverted, channels);
		}

    /**
     * Compute the PRF of a given secret shared value such that it is sent to a
     * third party without being revealed to third parties.
     *
     * The returned <code>Element[]</code> should be aggregated in an by the
     * third party receiver <code>Element[][]</code> and reconstructed using
     * <code>PedersonComm.plaintextExponentiateRecv</code>.
     */
    public Element[] computeSend(PedersonShare val, Channel[] channels) throws IOException {
        PedersonShare inverted = computeExponent(val, channels);
        return PedersonComm.plaintextBilinearExponentiateSend(inverted, channels.length);
    }

    /**
     * For PRFs computed with this private key, verify if the PRF of
     * <code>val</code> is <code>prf</code>. This computation is done locally
     * without any MPC.
     */
    public boolean verify(BigInteger val, Element prf) throws IOException {
        Element g_to_x_plus_key = PedersonShare.genDataG1_pp.pow(val);
        g_to_x_plus_key.mul(publicKey);
        Element check = PedersonShare.pairing.pairing(g_to_x_plus_key, prf);
        return check.isEqual(PedersonShare.genData);
    }

    /**
		 * Write custom serialization method so we can handle
		 * <code>Element</code> which does not implement
		 * <code>Serializable</code>.
		 *
		 * Remember to update any new class members here.
		 */
		private void writeObject(java.io.ObjectOutputStream stream) throws IOException {
        stream.writeObject(key);
        stream.writeObject(publicKey.toBytes());
        stream.writeObject(threshold);
    }

    private void readObject(java.io.ObjectInputStream stream) throws IOException, ClassNotFoundException {
        key = (PedersonShare)stream.readObject();
        publicKey = PedersonShare.groupG1.newElementFromBytes((byte[])stream.readObject());
        threshold = (int)stream.readObject();
    }
}
