package pederson;

import java.io.IOException;
import java.io.Serializable;
import java.lang.ClassCastException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;
import edu.biu.scapi.primitives.hash.openSSL.OpenSSLSHA512;

import pederson.PedersonShare;

public class PedersonComm {
		// TODO(venkat):
		//
		// - Descrive notation of 'channels' parameter in the functions
		//
		// - Check that only one element of 'channels' is null
		//   (corresponding to current player)

		private static SecureRandom random = new SecureRandom();
		
		/**
		 * Verify that all players have got the same
		 * commitment.<p>
		 *
		 * Communicates with other players who have called this
		 * function.<p>
		 *
		 * @param localCommitment Commitment this player has got
		 * @param channels Communication channels with other players. It
		 * is assumed that all players have this array in the same order
		 * (ie. position in array can be used as player id). At this
		 * player's position, channels should contain <code>null</code>
		 */
		private static boolean verifyCommitmentEquality(BigInteger[] localCommitment, Channel[] channels) throws IOException {
				assert channels != null && localCommitment != null;
				assert channels.length == localCommitment.length;
				assert channels.length > 0;

				// Send out commitment to everybody
				for (int i = 0; i < channels.length; ++i)
						if (channels[i] != null)
								channels[i].send(localCommitment);

				// Receive commitments from others;
				BigInteger[][] commitments = new BigInteger[channels.length][];
				for (int i  = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								commitments[i] = localCommitment; // Corresponds to this player
								continue;
						}
						try {
								commitments[i] = (BigInteger[])channels[i].receive();
						}
						catch (ClassNotFoundException e) {
								System.err.println(e.getMessage());
						}
				}

				// Verify that commitments are equal
				BigInteger[] commitment = commitments[0];
				for (int i = 1; i < commitments.length; ++i) {
						if (commitment.length != commitments[i].length)
								return false;
						for (int j = 0; j < commitment.length; ++j)
								if (commitment[j].compareTo(commitments[i][j]) != 0)
										return false;
				}
				return true;
		}

		/**
		 * Utility function to handle exceptions from the @reference
		 * Channel.receive method
		 */
		static private <T> T receive(Channel channel) throws IOException {
				assert channel != null;
				try {
						Serializable res = channel.receive();
						return (T)res;
				}
				catch (ClassNotFoundException e) {
						throw new IOException(e.getMessage());
				}
		}

		/**
		 * Toss <code>numbits</code> shared coins among all parties.<p>
		 * 
		 * No party can control what the result is. The toss is random as
		 * long as at-least one party is honest. This is the commitment
		 * phase of the coin toss.
		 *
		 * TODO(venkat): If somebody gives different commitment/random
		 * strings to different people, current implementation detects it
		 * but does not specify who cheated.
		 *
		 * @param numBits Number of bits worth of coins to toss (in
		 * parallel)
		 * @return Everybody's commitments. To be passed to {@link
		 * #coinTossDecommit(byte[][] commitments, Channel[]
		 * channels)}. Contains this players random bits instead of
		 * commitment
		 */
		private static byte[][] coinTossCommit(int numBits, Channel[] channels) throws IOException {
				// Choose our random bits and hash them
				byte[] myRandBits = new byte[1 + (numBits - 1) / 8];
				random.nextBytes(myRandBits);
				OpenSSLSHA512 commitHash = new OpenSSLSHA512();
				commitHash.update(myRandBits, 0, myRandBits.length);
				byte[] myCommitment = new byte[commitHash.getHashedMsgSize()];
				commitHash.hashFinal(myCommitment, 0);
				
				// Broadcast commitment
				for (Channel channel : channels)
						if (channel != null)
								channel.send((Serializable) myCommitment);

				// Get other's commitments
				byte[][] commitments = new byte[channels.length][];
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] != null) {
								commitments[i] = receive(channels[i]);
								if (commitments[i].length != myCommitment.length)
										throw new IOException("Commitment of unexpected length received");
						}
						else
								commitments[i] = myRandBits;
				}
				return commitments;
		}

		/**
		 * Toss shared coins among all parties.<p>
		 * 
		 * No party can control what the result is. The toss is random as
		 * long as at-least one party is honest. This is the de-commitment
		 * phase of the coin toss.
		 *
		 * TODO(venkat): If somebody gives different commitment/random
		 * strings to different people, current implementation detects it
		 * but does not specify who cheated.
		 *
		 * TODO(venkat): Make sure that a party cannot make their
		 * commitment depend on other's commitments
		 *
		 * @param commitments output of {@link #coinTossCommit(int
		 * numBits, Channel[] channels)}.
		 * @param channels <code>null</code> should be in the same place
		 * as in call to commit phase. This is NOT checked in this
		 * function.
		 * @return Result of coin toss.
		 */
		private static byte[] coinTossDecommit(byte[][] commitments, Channel[] channels) throws IOException {
				// Find <code>myRandBits</code>
				byte[] myRandBits = null;
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								assert myRandBits == null;
								myRandBits = commitments[i];
						}
				}
				assert myRandBits != null;
	
				// Broadcast actual bits
				for (Channel channel : channels)
						if (channel != null)
								channel.send((Serializable) myRandBits);

				// Get other's actual bits, verify commitment and find xor of
				// everybody's random strings.
				byte[] result = myRandBits.clone();
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null)
								continue;
						byte[] randBits = receive(channels[i]);
						if (randBits.length != myRandBits.length)
								throw new IOException("Random bits of unexpected length received.");
						
						OpenSSLSHA512 commitHash = new OpenSSLSHA512();
						commitHash.update(randBits, 0, myRandBits.length);
						byte[] expectedCommitment = new byte[commitHash.getHashedMsgSize()];
						commitHash.hashFinal(expectedCommitment, 0);
						if (!Arrays.equals(expectedCommitment, commitments[i]))
								throw new CheatAttemptException("Decommitment does not match commitment while coin tossing.");

						for (int j = 0; j < result.length; ++j)
								result[j] = (byte)(result[j] ^ randBits[j]);
				}

				// Broadcast our random value
				for (Channel channel : channels)
						if (channel != null)
								channel.send((Serializable) result);

				// Get other's random values and compare if they are the same
				for (Channel channel : channels) {
						if (channel == null)
								continue;
						byte[] othersResult = receive(channel);
						if (!Arrays.equals(result, othersResult))
								throw new CheatAttemptException("Somebody gave different 'broadcasts' to different people.");
				}

				return result;
		}

		/**
		 * Give the ith share to the player in the ith channel.
		 *
		 * @param The shares to distribute.
		 * @channels The players to distribute to. Assumes that array
		 * index serves as a proxy for player id.
		 */
		public static void shareSender(PedersonShare[] shares, Channel[] channels) throws IOException {
				if (shares.length != channels.length)
						throw new RuntimeException("Need exactly as many channels as shares.");
				if (!PedersonShare.verifyCommitmentEquality(shares))
						throw new RuntimeException("Public commitments on all these shares are not equal. If sent, other players will throw CheatAttemptException.");

				// Send the shares to all players
				PedersonShare myShare = null;
				for (int i = 0; i < shares.length; ++i) {
						if (channels[i] == null) {
								myShare = shares[i];
								assert myShare != null;
								continue;
						}
						channels[i].send((Serializable)shares[i]);
				}
				if (myShare == null)
						throw new RuntimeException("One of the channels must belong to this player (and be null).");

				// Participate in verification
				verifyCommitmentEquality(myShare.commitments, channels);
		}

		/**
		 * Receive share from another player.<p>
		 *
		 * @params recvFrom Index of the channel to which the
		 * share-supplying player is connected.
		 * @params channels Channels with which other players are
		 * connected. Assumes that array index is a proxy for player id.
		 */
		public static PedersonShare shareReceiver(int recvFrom, Channel[] channels) throws IOException, CheatAttemptException {
				assert channels[recvFrom] != null;
				PedersonShare share;
				try {
						share = (PedersonShare)channels[recvFrom].receive();
				}
				catch (ClassNotFoundException e) {
						throw new IOException(e.getMessage());
				}

				share.validate();
				verifyCommitmentEquality(share.commitments, channels);
				return share;
		}

		/**
		 * Combine shares with other players.<p>
		 *
		 * Tries to find threshold number of cooperating players.<p>
		 *
		 * @params share Share of this player.
		 * @params channels Channels with which other players are
		 * connection. Assumes that array index is a proxy for player id.
		 * @throws IOException If threshold number of cooperating players
		 * are not found. This indicates communication failure because
		 * that many players are trusted to be honest.
		 * @throws CheatAttemptException exception if values recieved from
		 * other players does not match commitment.
		 */
		public static BigInteger combineShares(PedersonShare share, int threshold, Channel[] channels) throws IOException, CheatAttemptException {
				for (Channel channel : channels)
						if (channel != null)
								channel.send((Serializable)share);

				PedersonShare[] shares = new PedersonShare[channels.length];
				shares[0] = share;
				int numSharesReceived = 1;
				for (Channel channel : channels) {
						if (channel == null)
								continue; //Ignore. Probably it is this player's position.
						try {
								shares[numSharesReceived] = (PedersonShare)channel.receive();
						}
						catch (IOException|ClassNotFoundException e) {
								continue;
						}
						++numSharesReceived;
				}
				if (numSharesReceived < threshold)
						throw new IOException("Insufficient number of shares received: " + numSharesReceived);

				if (!PedersonShare.verifyCommitmentEquality(shares))
						throw new CheatAttemptException("Everbody's public commitments are not the same");
				return PedersonShare.combineShares(shares);
		}

		public static PedersonShare multiply(PedersonShare val1, PedersonShare val2, Channel[] channels) throws IOException, CheatAttemptException {
				PedersonMultiply prover = new PedersonMultiply();

				// Share polynomial and get shares from others.
				
				// TODO(venkat): This can be done in parallel instead of
				// party-by-party.
				PedersonShare[] myPoly = prover.sharedPoly(val1, val2, channels.length);
				PedersonShare[] shares = new PedersonShare[channels.length];
				int ourIndex = -1;
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								shareSender(myPoly, channels);
								// Our share of our polynomial.
								shares[i] = myPoly[i];
								ourIndex = i;
						}
						else
								shares[i] = shareReceiver(i, channels);
				}
				
				// Commit to coin toss
				byte[][] coinTossCommitments = coinTossCommit(PedersonShare.modQ.bitLength() * channels.length, channels);

				// Broadcast commitment to ZKP
				for (Channel channel : channels)
						if (channel != null)
								channel.send(prover.zkpProverStep1());

				// Receive commitments to ZKP from others
				BigInteger[][] zkpCommitments = new BigInteger[channels.length][];
				for (int i = 0; i < channels.length; ++i)
						if (channels[i] != null)
								zkpCommitments[i] = receive(channels[i]);

				// Open coin toss
				byte[] coinToss = coinTossDecommit(coinTossCommitments, channels);
				System.out.println("Commitment length: " + coinToss.length + " " + PedersonShare.modQ.bitLength() + " " + channels.length);
				BigInteger[] challenges = new BigInteger[channels.length];
				for (int i = 0; i < channels.length; ++i) {
						int bitLength = 1 + (PedersonShare.modQ.bitLength() - 1) / 8;
						challenges[i] = new BigInteger(Arrays.copyOfRange(coinToss,
																															i * bitLength,
																															(i + 1) * bitLength)).
								mod(PedersonShare.modQ);
						System.out.println("Challenge: " + i + " " + challenges[i]);
				}

				// Broadcast our response
				for (Channel channel : channels)
						if (channel != null)
								channel.send(prover.zkpProverStep2(challenges[ourIndex]));

				// Get other's responses and verify them
				for (int i = 0; i < challenges.length; ++i) {
						if (channels[i] != null) {
								BigInteger[] response = receive(channels[i]);
								if (!prover.verifyProof(shares[i], zkpCommitments[i], challenges[i], response))
										System.out.println("ZKP Failed!"); //throw new CheatAttemptException("Zero Knowoledge Proof failed for player " + i);
						}
				}

				// Add shares to get share for result
				PedersonShare result = shares[0]; //.constMultiply(PedersonMultiply.getVandermondeInv(1, channels.length));
				for (int i = 1; i < shares.length; ++i) {
						//assert shares[i].index.compareTo(BigInteger.valueOf(ourIndex)) == 0;
						//BigInteger lambda = PedersonMultiply.getVandermondeInv(i + 1, channels.length);
						result = result.add(shares[i]);
				}
				return result;
		}
}
