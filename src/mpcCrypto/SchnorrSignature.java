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
		public static SchnorrSignatureShare[] sign(BigInteger message, BigInteger privateKey, boolean publicKeyHidden, int threshold, int numShares) {
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

				System.out.println("message: " + message + "\nprivateKey: " + privateKey + "\npublicKey: " + generator.modPow(privateKey, modQ) + "\nk = " + k + "\nr = " + r + "\ne = " + e + "\ns: " + s);
				
				// Make the shares
				PedersonShare[] publicKeyShares = PedersonShare.shareValue(generator.modPow(privateKey, modQ), threshold, numShares);
				PedersonShare[] messageShares = PedersonShare.shareValue(message, threshold, numShares);
				PedersonShare[][] sShares = new PedersonShare[modQ.bitLength()][];
				BigInteger gPow = generator;
				for (int i = 0; i < modQ.bitLength(); ++i) {
						sShares[i] = PedersonShare.shareValue(s.testBit(i)?BigInteger.ONE:gPow.modInverse(modQ),
																									threshold,
																									numShares);
						gPow = gPow.multiply(gPow).mod(modQ);
				}
				SchnorrSignatureShare[] result = new SchnorrSignatureShare[numShares];

				// Package information
				for (int i = 0; i < numShares; ++i) {
						result[i] = new SchnorrSignatureShare();
						if (publicKeyHidden)
								result[i].publicKey = publicKeyShares[i];
						else
								result[i].publicKeyPt = PedersonShare.combineShares(publicKeyShares);
						result[i].message = messageShares[i];
						result[i].e = e;
						result[i].s = new PedersonShare[modQ.bitLength()];
						for (int j = 0; j < modQ.bitLength(); ++j)
								result[i].s[j] = sShares[j][i];
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

				// Find g^s TODO(venkat): Confirm that bits of s are either 0
				// or (g^i)^{-1}
				BigInteger gPow = generator;
				PedersonShare g_s = sign.s[0].constMultiply(gPow);
				for (int i = 1; i < modQ.bitLength(); ++i) {
						gPow = gPow.multiply(gPow).mod(modQ);
						g_s = PedersonComm.multiply(g_s, sign.s[i].constMultiply(gPow), channels);
				}

				// Hash M || r
				BigInteger mPlusR;
				if (sign.publicKeyHidden) {
						PedersonShare y_e = PedersonComm.exponentiate(sign.publicKey, sign.e, channels);
						mPlusR = PedersonComm.combineShares(PedersonComm.multiply(y_e, g_s, channels)
																													 .add(sign.message),
																													 channels);
				}
				else {
						assert(false);
						// TODO: verify all thresholds in sign are same
						// PedersonShare mpr = PedersonShare.shareConstValue(sign.publicKeyPt.modPow(sign.e, modQ),
						// 						     sign.message.threshold,
						// 						     channels.length).add(sign.message);
						// mPlusR = PedersonComm.combineShares(mpr, channels);
						mPlusR = null;
				}

				
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
