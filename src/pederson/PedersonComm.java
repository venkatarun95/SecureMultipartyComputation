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

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import crypto.SchnorrZKP;
import pederson.PedersonShare;

/**
 * Interface class that encapsulates all protocols requiring
 * communication in multi-party computation using Pederson secret
 * sharing.
 *
 * Most functions take an argument <code>channels</code> which is a
 * complete, ordered list of channels to which other peersre
 * connected. The order of parties in this list must be the same for
 * all peers/players. Exactly one of these must be <code>null</code>
 * which corresponds to this party (other parties would have a channel
 * connecting to this party in that position).
 *
 * When a cheat attempt is detected, currently this class throws a
 * CheatAttemptException and halts protocol execution mid-way, even if
 * the protocol can be completed without aid of other parties.
 */
public class PedersonComm {
    // TODO(venkat):
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
    private static void verifyCommitmentEquality(Element[] localCommitment, Channel[] channels) throws IOException {
        assert channels != null && localCommitment != null;
        assert channels.length == localCommitment.length;
        assert channels.length > 0;

        // Send out commitment to everybody
        for (int i = 0; i < channels.length; ++i)
            if (channels[i] != null)
                sendElems(localCommitment, channels[i]);

        // Receive commitments from others;
        Element[][] commitments = new Element[channels.length][];
        for (int i  = 0; i < channels.length; ++i) {
            if (channels[i] == null) {
                commitments[i] = localCommitment; // Corresponds to this player
                continue;
            }
						commitments[i] = receiveElems(channels[i]);
        }

        // Verify that commitments are equal
        Element[] commitment = commitments[0];
        for (int i = 1; i < commitments.length; ++i) {
            if (commitment.length != commitments[i].length)
                throw new RuntimeException("Different parties have different number of commitments.");
            for (int j = 0; j < commitment.length; ++j) {
								// TODO(venkat): Throw exception here. Don't wait for it to go outside.
                if (!commitment[j].isEqual(commitments[i][j]))
                    throw new RuntimeException("Different parties have different commitments");
						}
        }
    }

    /**
     * Utility function to recieve data from channel. Handy for
     * handling exceptions from the @reference Channel.receive method.
     *
     * TODO: Check that the deserialization has the right type.
     */
    @SuppressWarnings("unchecked")
    static private <T> T receive(Channel channel) throws IOException {
        assert channel != null;
        try {
            return (T)channel.receive();
        }
        catch (ClassNotFoundException e) {
            throw new IOException(e.getMessage());
        }
    }

		/**
     * Utility function to send array of elements to channel. Handy
     * for converting <code>Element[]</code> to <code>byte[][]</code>.
     */
		static private void sendElems(Element[] elems, Channel channel) throws IOException {
				byte[][] toSend = new byte[elems.length][];
				for (int i = 0; i < toSend.length; ++i)
						toSend[i] = elems[i].toBytes();
				channel.send(toSend);
		}

		/**
     * Utility function to receive array of elements from
     * channel. Handy for converting <code>byte[][]</code> to
     * <code>Element[]</code> and handling exceptions from the @reference
     * Channel.receive method
     */
		static private Element[] receiveElems(Channel channel) throws IOException {
        assert channel != null;
        try {
            byte[][] recvd = (byte[][])channel.receive();
						Element[] res = new Element[recvd.length];
						for (int i = 0; i < res.length; ++i)
								res[i] = PedersonShare.group.newElementFromBytes(recvd[i]);
            return res;
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
								assert myShare == null;
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
    public static BigInteger combineShares(PedersonShare share, Channel[] channels) throws IOException, CheatAttemptException {
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
        if (numSharesReceived < share.threshold)
            throw new IOException("Insufficient number of shares received: " + numSharesReceived);

        if (!PedersonShare.verifyCommitmentEquality(shares))
            throw new CheatAttemptException("Everbody's public commitments are not the same");
        return PedersonShare.combineShares(shares);
    }

    /**
     * Multiply two shared values.<p>
     *
     * Requires interaction with 2 * threshold + 1 peers.
     */
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
        Element[] ourZkpCommitment = prover.zkpProverStep1();
        for (Channel channel : channels)
            if (channel != null)
                sendElems(ourZkpCommitment, channel);

        // Receive commitments to ZKP from others
        Element[][] zkpCommitments = new Element[channels.length][];
        for (int i = 0; i < channels.length; ++i)
            if (channels[i] != null) {
                zkpCommitments[i] = receiveElems(channels[i]);
            }

        // Open coin toss
        byte[] coinToss = coinTossDecommit(coinTossCommitments, channels);
        BigInteger[] challenges = new BigInteger[channels.length];
        for (int i = 0; i < channels.length; ++i) {
            int bitLength = 1 + (PedersonShare.modQ.bitLength() - 1) / 8;
            challenges[i] = new BigInteger(Arrays.copyOfRange(coinToss,
                                                              i * bitLength,
                                                              (i + 1) * bitLength)).
                mod(PedersonShare.modQ);
        }

        // Broadcast our response
        BigInteger[] zkpResponse = prover.zkpProverStep2(challenges[ourIndex]);
        for (Channel channel : channels)
            if (channel != null)
                channel.send(zkpResponse);

        // Get other's responses and verify them
        for (int i = 0; i < challenges.length; ++i) {
            if (channels[i] != null) {
                BigInteger[] response = receive(channels[i]);
                if (!prover.verifyProof(i + 1, shares[i], zkpCommitments[i], challenges[i], response))
                    throw new CheatAttemptException("Zero Knowoledge Proof failed for player " + i);
            }
        }

        // Add shares to get share for result
        PedersonShare result = shares[0].constMultiply(PedersonMultiply.getVandermondeInv(1, 1, channels.length));
        for (int i = 1; i < shares.length; ++i) {
            BigInteger lambda = PedersonMultiply.getVandermondeInv(i + 1, 1, channels.length);
            result = result.add(shares[i].constMultiply(lambda));
        }
        return result;
    }

    /**
     * Generate share of a random number that no party knows about as
     * long as one of them is honest. The random number is uniformly
     * distributed in 0 to modQ - 1.
     *
     * @param threshold The reveal threshold of the shares generated.
     */
    public static PedersonShare shareRandomNumber(int threshold, Channel[] channels) throws IOException, CheatAttemptException {
        // Generate a shares of a random number
        BigInteger rNum = new BigInteger(PedersonShare.modQ.bitLength(), random).mod(PedersonShare.modQ);
        PedersonShare[] shares = PedersonShare.shareValue(rNum, threshold, channels.length);

        // Send the shares and receive shares from others.

        // TODO: This can be done in parallel instead of one-by-one
        PedersonShare result = null;
        for (int i = 0; i < channels.length; ++i) {
            if (channels[i] == null) {
                shareSender(shares, channels);
                if (result == null)
                    result = shares[i];
								else
										result = result.add(shares[i]);
            }
            else {
                PedersonShare received = shareReceiver(i, channels);
                if (result == null)
                    result = received;
								else
										result = result.add(received);
            }
        }

        return result;
    }

    /**
     * Given g^{valData} of enough shares, computes the reconstructed
     * value of the first <code>threshold</code> available shares.
     *
     * @param shares Shares using which value is to be
     * reconstructed. If a particular share is not available, there
     * should be a null in that position. Position of share is
     * considered to be (index of share - 1)
     */
    private static Element reconstructExponentiatedShares(Element[] shares, int threshold, int numShares) {
        assert numShares >= shares.length;
        Element result = PedersonShare.group.newElement(1);
        BigInteger modQ = PedersonShare.modQ;
        int numNonNullShares = 0;
        // Make all shares we are not going to use null
        for (int i = 0; i < shares.length; ++i) {
            if (shares[i] == null)
                continue;
            ++numNonNullShares;
            if (numNonNullShares > threshold)
                shares[i] = null;
        }
        if (numNonNullShares < threshold)
            throw new RuntimeException("Insufficient number of shares to compute value + " + numNonNullShares);

        for (int i = 0; i < shares.length; ++i) {
            if (shares[i] == null)
                continue;

            BigInteger coeff = BigInteger.ONE;
            for (int j = 1; j <= numShares; ++j) {
                if (j == i + 1)
                    continue;
                if (shares[j - 1] == null)
                    continue;
                coeff = coeff.multiply(BigInteger.valueOf(j)).mod(modQ);
                coeff = coeff.multiply(BigInteger.valueOf(j - i - 1).modInverse(modQ)).mod(modQ);
            }
            result.mul(shares[i].pow(coeff));
        }
        return result;
    }

    /**
     * Given g^{valData} of enough shares, computes the reconstructed value of
     * the first <code>threshold</code> available shares. Prouces results in G1
     * group.
     *
     * @param shares Shares using which value is to be
     * reconstructed. If a particular share is not available, there
     * should be a null in that position. Position of share is
     * considered to be (index of share - 1)
     */
    private static Element reconstructBilinearExponentiatedShares(Element[] shares, int threshold, int numShares) {
        assert numShares >= shares.length;
        Element result = PedersonShare.groupG1.newElement(1);
        BigInteger modQ = PedersonShare.modQ;
        int numNonNullShares = 0;
        // Make all shares we are not going to use null
        for (int i = 0; i < shares.length; ++i) {
            if (shares[i] == null)
                continue;
            ++numNonNullShares;
            if (numNonNullShares > threshold)
                shares[i] = null;
        }
        if (numNonNullShares < threshold)
            throw new RuntimeException("Insufficient number of shares to compute value + " + numNonNullShares);

        for (int i = 0; i < shares.length; ++i) {
            if (shares[i] == null)
                continue;

            BigInteger coeff = BigInteger.ONE;
            for (int j = 1; j <= numShares; ++j) {
                if (j == i + 1)
                    continue;
                if (shares[j - 1] == null)
                    continue;
                coeff = coeff.multiply(BigInteger.valueOf(j)).mod(modQ);
                coeff = coeff.multiply(BigInteger.valueOf(j - i - 1).modInverse(modQ)).mod(modQ);
            }
            result.mul(shares[i].pow(coeff));
        }
        return result;
    }


		/**
		 * Computes g ^ {shared value} where g is
		 * <code>PedersonShare.genData</code>.
		 */
    public static Element plaintextExponentiate(PedersonShare share, Channel[] channels) throws IOException, CheatAttemptException {
        BigInteger modQ = PedersonShare.modQ;
				// Broadcast g^share and h^share
				SchnorrZKP exp1 = new SchnorrZKP(PedersonShare.genData, modQ, share.valData);
				SchnorrZKP exp2 = new SchnorrZKP(PedersonShare.genVerif, modQ, share.valVerif);
				SchnorrZKP[] exp1s = new SchnorrZKP[channels.length];
				SchnorrZKP[] exp2s = new SchnorrZKP[channels.length];
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								exp1s[i] = exp1;
								exp2s[i] = exp2;
								continue;
						}
						channels[i].send(exp1.toByteArrays());
						channels[i].send(exp2.toByteArrays());
				}

				// Get other people's 'broadcast's. Note we needn't check if
				// same value is broadcast to all since we are verifying the
				// commitment anyway.
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null)
								continue;
						exp1s[i] = new SchnorrZKP(receive(channels[i]), PedersonShare.group);
						exp2s[i] = new SchnorrZKP(receive(channels[i]), PedersonShare.group);
            exp1s[i].verify();
            exp2s[i].verify();
						Element check = exp1s[i].a.duplicate().mul(exp2s[i].a);
						if (!check.isEqual(share.computeMac(BigInteger.valueOf(i+1)))) {
								System.err.println("Verification failed for party " + (i+1) + " during plaintext exponentiation.");
								exp1s[i] = null;
								exp2s[i] = null;
						}
				}

				// Interpolate in the exponent to get the result
        Element[] exps = new Element[exp1s.length];
        for (int i = 0; i < exp1s.length; ++i) {
            exps[i] = exp1s[i].a;
        }
        return reconstructExponentiatedShares(exps, share.threshold, channels.length);
		}

    /**
     * For use when parties need to exponentiate their shares, but reveal it
     * only to a third party.
     *
     * @param share Our share of value to be exponentiated.
     * @numShares Maximun number of parties holding the shares (can be an
     * overestimate, but should be same for all parties).
     * @return <code>2 + numShares</code> elements, which should be sent to the third party.
     */
    public static Element[] plaintextExponentiateSend(PedersonShare share, int numShares) {
        Element[] res = new Element[2 + numShares];
        res[0] = PedersonShare.genData_pp.pow(share.valData);
        res[1] = PedersonShare.genVerif_pp.pow(share.valVerif);
        for (int i = 0; i < numShares; ++i) {
            res[i + 2] = share.computeMac(BigInteger.valueOf(i+1));
        }
        return res;
    }

    /**
     * For use when parties need to exponentiate their shares, but reveal if
     * only to a third party.
     *
     * @params expShares Array of <code>Element[]</code> returned by
     * <code>plaintextExponentiateSend</code>. These must be in order
     * @return Reconstructed value.
     * TODO (venkat) Make sure that even if everybody does not comply, we can
     * still reproduce shares.
     */
    public static Element plaintextExponentiateRecv(Element[][] expShares, int threshold, int numShares) {
        if(expShares.length < threshold)
            throw new RuntimeException("Do not have enough shares to reconstruct exponentiated value.");
        // Check the commitments
        for (int i = 0; i < expShares.length; ++i) {
            // Check whether the MACs everybody sent are identical
            if (expShares[0].length != expShares[i].length)
                throw new RuntimeException("Different people have sent different number of MACs.");
            for (int j = 2; j < expShares[0].length; ++j)
                if (!expShares[0][j].isEqual(expShares[i][j]))
                    throw new RuntimeException("Different people have sent different MACs.");

            // Check if the sent values are valid.
            Element check = expShares[i][0].duplicate().mul(expShares[i][1]);
            if (!check.isEqual(expShares[0][i+2]))
                throw new RuntimeException("Verification failed for party " + (i+1) + ".");
        }

        // Interpolate in the exponent to get the result
        Element[] shares = new Element[expShares.length];
        for (int i = 0; i < expShares.length; ++i) {
            shares[i] = expShares[i][0];
        }
        return reconstructExponentiatedShares(shares, threshold, numShares);
    }

    /**
     * For use when parties need to exponentiate their shares, but reveal it
     * only to a third party. Produces results in G1 group.
     *
     * @param share Our share of value to be exponentiated.
     * @numShares Maximun number of parties holding the shares (can be an
     * overestimate, but should be same for all parties).
     * @return <code>2 + numShares</code> elements, which should be sent to the third party.
     */
    public static Element[] plaintextBilinearExponentiateSend(PedersonShare share, int numShares) {
        Element[] res = new Element[2 + numShares];
        res[0] = PedersonShare.genDataG1_pp.pow(share.valData);
        res[1] = PedersonShare.genVerifG1_pp.pow(share.valVerif);
        for (int i = 0; i < numShares; ++i) {
            res[i + 2] = share.computeMac(BigInteger.valueOf(i+1));
        }
        return res;
    }

    /**
     * For use when parties need to exponentiate their shares, but reveal if
     * only to a third party. Produces results in G1 group.
     *
     * @params expShares Array of <code>Element[]</code> returned by
     * <code>plaintextExponentiateSend</code>. These must be in order
     * @return Reconstructed value.
     * TODO (venkat) Make sure that even if everybody does not comply, we can
     * still reproduce shares.
     */
    public static Element plaintextBilinearExponentiateRecv(Element[][] expShares, int threshold, int numShares) {
        if(expShares.length < threshold)
            throw new RuntimeException("Do not have enough shares to reconstruct exponentiated value.");
        // Check the commitments
        for (int i = 0; i < expShares.length; ++i) {
            // Check whether the MACs everybody sent are identical
            if (expShares[0].length != expShares[i].length)
                throw new RuntimeException("Different people have sent different number of MACs.");
            for (int j = 2; j < expShares[0].length; ++j)
                if (!expShares[0][j].isEqual(expShares[i][j]))
                    throw new RuntimeException("Different people have sent different MACs.");

            // Check if the sent values are valid.
            Element paired1 = PedersonShare.pairing.pairing(expShares[i][0], PedersonShare.genDataG1);
            Element paired2 = PedersonShare.pairing.pairing(expShares[i][1], PedersonShare.genVerifG1);
						Element check = paired1.duplicate().mul(paired2);
            if (!check.isEqual(expShares[0][i+2]))
                throw new RuntimeException("Verification failed for party " + (i+1) + ".");
        }

        // Interpolate in the exponent to get the result
        Element[] shares = new Element[expShares.length];
        for (int i = 0; i < expShares.length; ++i) {
            shares[i] = expShares[i][0];
        }
        return reconstructBilinearExponentiatedShares(shares, threshold, numShares);
    }


    /**
     * Exponentiate the G1 group of the bilinear pairing to the value
     * represented by <code>share</code>. Works when sharing is done
     * with commitments in GT.
     *
     * This is useful because operations on GT are often much faster.
     */
    public static Element plaintextBilinearExponentiate(PedersonShare share, Channel[] channels) throws IOException {
				// Broadcast g^share and h^share
        BigInteger modQ = PedersonShare.modQ;
				SchnorrZKP exp1 = new SchnorrZKP(PedersonShare.genDataG1, modQ, share.valData);
				SchnorrZKP exp2 = new SchnorrZKP(PedersonShare.genVerifG1, modQ, share.valVerif);
				SchnorrZKP[] exp1s = new SchnorrZKP[channels.length];
				SchnorrZKP[] exp2s = new SchnorrZKP[channels.length];
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								exp1s[i] = exp1;
								exp2s[i] = exp2;
								continue;
						}
						//System.out.println(share.valData.toString());
						channels[i].send(exp1.toByteArrays());
						channels[i].send(exp2.toByteArrays());
				}

				// Get other people's 'broadcast's. Note we needn't check if
				// same value is broadcast to all since we are verifying the
				// commitment anyway.
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null)
								continue;
						exp1s[i] = new SchnorrZKP(receive(channels[i]), PedersonShare.groupG1);
						exp2s[i] = new SchnorrZKP(receive(channels[i]), PedersonShare.groupG1);
            exp1s[i].verify();
            exp2s[i].verify();
            Element paired1 = PedersonShare.pairing.pairing(exp1s[i].a, PedersonShare.genDataG1);
            Element paired2 = PedersonShare.pairing.pairing(exp2s[i].a, PedersonShare.genVerifG1);
						Element check = paired1.duplicate().mul(paired2);
						if (!check.isEqual(share.computeMac(BigInteger.valueOf(i+1)))) {
								System.err.println("Verification failed for party " + (i+1) + " during plaintext exponentiation.");
								exp1s[i] = null;
								exp2s[i] = null;
						}
				}

				// Interpolate in the exponent to get the result
				Element result = PedersonShare.groupG1.newElement(1);
				int numUsed = 0;
        for (int i = 0; i < exp1s.length; ++i) {
            if (exp1s[i] == null)
                continue;
						// if (numUsed >= share.threshold)
						// 		break;
						++numUsed;

            BigInteger coeff = BigInteger.ONE;
            for (int j = 1; j <= exp1s.length; ++j) {
                if (j == i + 1)
                    continue;
                if (exp1s[j - 1] == null)
                    continue;
                coeff = coeff.multiply(BigInteger.valueOf(j)).mod(modQ);
                coeff = coeff.multiply(BigInteger.valueOf(j - i - 1).modInverse(modQ)).mod(modQ);
            }
						//System.out.println(i + " " + coeff);
            result.mul(exp1s[i].a.pow(coeff));
        }
				if (numUsed < share.threshold)
						throw new RuntimeException("Did not receive enough correct shares from others to exponentiate.");
				return result;
    }
}
