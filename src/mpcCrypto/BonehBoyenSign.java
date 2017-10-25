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
 * Class for computing Boneh-Boyen signatures when both secret key and
 * message are secret shared. Needs <code>PedersonShare</code> to use
 * a group that is G = G_1 = G_2 in a bilinear pairing.
 */
public class BonehBoyenSign {
		PedersonShare keyX, keyY;
		int threshold;
		Channel[] channels;

		public BonehBoyenSign(int a_threshold, Channel[] a_channels) throws IOException {
				threshold = a_threshold;
				channels = a_channels;

				keyX = PedersonComm.shareRandomNumber(threshold, channels);
				keyY = PedersonComm.shareRandomNumber(threshold, channels);
		}

		/**
		 * Compute a signature on the given secret shared message.
		 *
		 * Currently doesn't return anything. This is just for profiling.
		 */
		public void compute(PedersonShare msg) throws IOException {
				PedersonShare toInvertP1 = keyX.add(msg);
				PedersonShare r = PedersonComm.shareRandomNumber(threshold, channels);
				PedersonShare toInvertP2 = PedersonComm.multiply(r, keyY, channels);
				PedersonShare toInvert = toInvertP1.add(toInvertP2);
				
				PedersonShare blind = PedersonComm.shareRandomNumber(threshold, channels);
				PedersonShare blinded = PedersonComm.multiply(toInvert, blind, channels);
				BigInteger revealed = PedersonComm.combineShares(blinded, channels);
				BigInteger blindInverted = revealed.modInverse(PedersonShare.modQ);
				PedersonShare revealedShare = PedersonShare.shareConstValue(blindInverted, threshold, channels.length)[msg.getIndex()-1];
				PedersonShare inverted = PedersonComm.multiply(revealedShare, blind, channels);
        Element res = PedersonComm.plaintextBilinearExponentiate(inverted, channels);
		}
}
