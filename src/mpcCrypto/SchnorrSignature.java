package mpcCrypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA256;

import pederson.PedersonShare;
import pederson.PedersonComm;

import mpcCrypto.SchnorrSignatureShare;

/**
 * Implements anonymous multi-party Schnorr signature verification.
 *
 * Uses subgroup of size PedersonShare.modQ in group
 * PedersonShare.mod. modQ = 2 * mod.
 */
public class SchnorrSignature {
		// TODO: Choose a generator properly. It may need to be
		// independent of generators used in Pederson secret sharing. Also
		// verify that using Z_q is ok and we do not need a Schnorr group.
		private static BigInteger generator = BigInteger.valueOf(2);

		/**
		 * Returns shares of a schnorr signature that can safely be shared
		 * among <code>numShares</code> parties.
		 *
		 * At-least <code>threshold</threshold> of these shares are
		 * required to obtain any information about the identity of the
		 * signer or contents of the message. This is a computational
		 * guarantee.
		 */
		public static SchnorrSignatureShare[] sign(BigInteger message, BigInteger privateKey, int threshold, int numShares) {
				SecureRandom random = new SecureRandom();
				BigInteger modQ = PedersonShare.modQ;
				// TODO: Verify!! modQ also probably needs to be a safe prime now.
				BigInteger modQMinusOne = modQ.subtract(BigInteger.ONE);

				// Choose random number
				BigInteger k = new BigInteger(modQ.bitLength(), random).mod(modQ);
				BigInteger r = generator.modPow(k, modQ);

				// Hash M || r
				OpenSSLSHA256 hash = new OpenSSLSHA256();
				BigInteger mPlusR = message.add(r).mod(modQ);
				hash.update(mPlusR.toByteArray(), 0, mPlusR.toByteArray().length);
				byte[] hashBytes = new byte[hash.getHashedMsgSize()];
				hash.hashFinal(hashBytes, 0);
				// Compute e and r
				BigInteger e = new BigInteger(hashBytes).mod(modQ);
				BigInteger s = k.subtract(privateKey.multiply(e)).mod(modQMinusOne);

				// System.out.println("message: " + message + "\nprivateKey: " + privateKey + "\npublicKey: " + generator.modPow(privateKey, modQ) + "\nk = " + k + "\nr = " + r + "\ne = " + e + "\ns: " + s);
				
				// Make the shares
				PedersonShare[] publicKeyShares = PedersonShare.shareValue(generator.modPow(privateKey, modQ), threshold, numShares);
				PedersonShare[] messageShares = PedersonShare.shareValue(message, threshold, numShares);
				SchnorrSignatureShare[] result = new SchnorrSignatureShare[numShares];
				for (int i = 0; i < numShares; ++i) {
						result[i] = new SchnorrSignatureShare();
						result[i].publicKey = publicKeyShares[i];
						result[i].message = messageShares[i];
						result[i].e = e;
						result[i].s = s;
				}

				return result;
		}

		/**
		 * Run a multi-party computation to determine if given share of a
		 * sign is valid for the message in the signature.
		 */
		public static boolean verify(SchnorrSignatureShare sign, Channel[] channels) throws IOException, CheatAttemptException {
				// Notation: variable name x_y denotes x^y
				BigInteger modQ = PedersonShare.modQ;				
				PedersonShare y_e = PedersonComm.exponentiate(sign.publicKey, sign.e, channels);
				BigInteger g_s = generator.modPow(sign.s, modQ);
				BigInteger mPlusR = PedersonComm.combineShares(y_e.constMultiply(g_s).add(sign.message), channels);
				// Hash M || r
				OpenSSLSHA256 hash = new OpenSSLSHA256();
				hash.update(mPlusR.toByteArray(), 0 , mPlusR.toByteArray().length);
				byte[] hashBytes = new byte[hash.getHashedMsgSize()];
				hash.hashFinal(hashBytes, 0);
				BigInteger constructedE = new BigInteger(hashBytes).mod(modQ);
				if (sign.e.compareTo(constructedE) != 0)
						return false;
				return true;
		}
}
