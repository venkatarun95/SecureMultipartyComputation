package mpcCrypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import pederson.PedersonShare;
import pederson.PedersonComm;

/**
 * Class for PRF computation in a multi-party setting. Needs
 * <code>PedersonShare</code> to use a group that satisfies the
 * q-DBDHI (q-Decisional Bilinear Diffie Hellman Inversion)
 * assumption.
 */
public class PRF {
		PedersonShare key;
		int threshold;
		Channel[] channels;

		public PRF(int a_threshold, Channel[] a_channels) throws IOException {
				threshold = a_threshold;
				channels = a_channels;

				key = PedersonComm.shareRandomNumber(threshold, channels);
		}

		/**
		 * Reveals the secret key for this PRF in plaintext.
		 *
		 * Use very carefully. Revealing key will compromize all values
		 * whose PRF has been computed.
		 */
		public BigInteger revealKey() throws IOException {
				return PedersonComm.combineShares(key, channels);
		}

    private PedersonShare computeExponent(PedersonShare val) throws IOException {
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
		public Element compute(PedersonShare val) throws IOException {
				PedersonShare inverted = computeExponent(val);
				return PedersonComm.plaintextExponentiate(inverted, channels);
		}

    /**
     * Compute the PRF of a given secret shared value such that it is sent to a
     * third party without being revealed to third parties.
     *
     * The returned <code>Element[]</code> should be aggregated in an by the
     * third party receiver <code>Element[][]</code> and reconstructed using
     * <code>PedersonComm.plaintextExponentiateRecv</code>.
     */
    public Element[] computeSend(PedersonShare val) throws IOException {
        PedersonShare inverted = computeExponent(val);
        return PedersonComm.plaintextExponentiateSend(inverted, channels.length);
    }
}
