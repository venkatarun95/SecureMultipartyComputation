package pederson;

import java.io.IOException;
import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;

import pederson.PedersonShare;
import pederson.PedersonComm;

public class ClearTextProxy {
    PedersonShare[] randomKey;
    int threshold;
    int numShares;

    /**
     * Instantiate generator by sharing a random key. Use one
     * generator for each set of objects to be matched.
     *
     * @param numBits Number of bits of input this generator should
     * handle.
     * @param threshold Reveal threshold for secret sharing.
     */
    public ClearTextProxy(int numBits, int a_threshold, Channel[] channels) throws IOException {
        threshold = a_threshold;
        numShares = channels.length;
        randomKey = new PedersonShare[numBits + 1];
        for (int i = 0; i < numBits + 1; ++i)
            randomKey[i] = PedersonComm.shareRandomNumber(threshold, channels);
    }

    /**
     * Generate a clear-text-proxy of the bit-shared secret using the
     * given random key and the given peers.
     *
     * TODO(venkat): Does not ensure that the shared bits are actually
     * 0/1.
     */
    public BigInteger generateCtp(PedersonShare[] bits, Channel[] channels) throws IOException, CheatAttemptException {
        if (bits.length + 1 != randomKey.length)
            throw new RuntimeException("Number of bits in plaintext needs to be the same as in the key (as specified in constructor).");
        if (numShares != channels.length)
            throw new RuntimeException("Number of channels given during construction does not match number of channels now.");
        // TODO(venkat): verify that all bits have the same index

        // Share of the final result
        PedersonShare resultShare = randomKey[0];
        PedersonShare pedersonOne = PedersonShare.shareConstValue(BigInteger.valueOf(1),
                                                                  threshold,
                                                                  channels.length)[bits[0].index.intValue() - 1];

        for (int i = 0; i < bits.length; ++i) {
            PedersonShare term = PedersonComm.multiply(randomKey[i+1], bits[i], channels);
            term = term.add(pedersonOne);
            term = term.add(bits[i].constMultiply(PedersonShare.modQ.subtract(BigInteger.ONE)));
            resultShare = PedersonComm.multiply(resultShare, term, channels);
        }

        // TODO(venkat): Choose a proper generator
        return PedersonComm.plaintextExponentiate(PedersonShare.genVerif, resultShare, channels);
    }
}
