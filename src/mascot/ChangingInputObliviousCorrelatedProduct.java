package mascot;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.ArrayList;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.io.IOException;
import java.nio.ByteBuffer;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralSInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousSender;

/**
	 Implements Player A in MASCOT paper's COPEe protocol.
*/
public class ChangingInputObliviousCorrelatedProduct {
		private int securityK;
		private ArrayList<byte[]> seeds0, seeds1;
		// WARNING: This is a stop-gap solution only. Use a
		// cryptographically strong generator in production.
		private Random[] sharedRand0, sharedRand1;

		/**
		 * Runs the initialization step. All calls to extend afterward are
		 *	 very cheap.
		 * @param ipAddr IP address of this player which acts as a
		 * server.
		 * @param port Port of this player. Connection is made by a C
		 * library, so an unused port is required. It is freed after this
		 * function call.
		 * @param securityK Security parameter. Equals the number of OTs
		 * and the size of each OT. While these can be varied separately,
		 * it makes sense for them to be equal.
		 */
		public ChangingInputObliviousCorrelatedProduct (String ipAddr, int port, int a_securityK) {
				securityK = 8*(a_securityK / 8);
				sharedRand0 = new Random[securityK];
				sharedRand1 = new Random[securityK];

				// Select random seeds
				Random random = new Random();
				byte[] serSeeds0 = new byte[securityK * securityK / 8];
				byte[] serSeeds1 = new byte[securityK * securityK / 8];
				random.nextBytes(serSeeds0);
				random.nextBytes(serSeeds1);
				
				// Split the random seeds for easy retrieval later.
				seeds0 = new ArrayList<byte[]>();
				seeds1 = new ArrayList<byte[]>();
				byte[] tempSeed0 = new byte[securityK / 8];
				byte[] tempSeed1 = new byte[securityK / 8];
				for (int i = 0; i < securityK * securityK / 8; ++i) {
						tempSeed0[i % (securityK / 8)] = serSeeds0[i];
						tempSeed1[i % (securityK / 8)] = serSeeds1[i];
						if (i % (securityK / 8) == securityK / 8 - 1) {
								seeds0.add(tempSeed0);
								seeds1.add(tempSeed1);
								sharedRand0[i * 8 / securityK] = new Random(ByteBuffer.wrap(tempSeed0).getLong());
								sharedRand1[i * 8 / securityK] = new Random(ByteBuffer.wrap(tempSeed1).getLong());
								tempSeed0 = new byte[securityK / 8];
								tempSeed1 = new byte[securityK / 8];
						}						
				}

				// OT the seeds
				OTExtensionMaliciousSender ot = new OTExtensionMaliciousSender(ipAddr,
																																			 port,
																																			 securityK);
				ot.transfer(null, new OTExtensionGeneralSInput(serSeeds0, serSeeds1, securityK));
				// for (int i = 0; i < seeds0.size(); ++i) {
				// 		for (int j = 0; j < seeds0.get(i).length; ++ j)
				// 				System.out.print(seeds0.get(i)[j] + ":" + seeds1.get(i)[j] + " ");
				// 		System.out.println("");
				// }
				ot.releaseResources();
		}

		/**
		 * Returns additive shares of x_i s.\Delta, where \Delta is
		 * the fixed input of the other player.<p>
		 * 
		 * Calling this only requires one cheap transfer of data from this
		 * party to the other.
		 * @param List of x_i s. Each x_i must be of size securityK.
		 * @param channel Channel to use.
		 * @return List of shares. Each share is a securityK bit value
		 * (index 0 is MSB).
		 */
		public ArrayList<BigInteger> extend(ArrayList<BigInteger> xList, Channel channel) throws IOException {
				ArrayList<BigInteger> result = new ArrayList<BigInteger>();
				for (BigInteger x : xList) {
						if (x.bitLength() > securityK)
								throw new RuntimeException("Incorrect length of x_i. Expecting securityK bits. " + x.bitLength() + " vs " + securityK + " bits");
						byte[] t0 = new byte[securityK / 8], t1 = new byte[securityK / 8];
						BigInteger share = new BigInteger("0");
						for (int i = 0; i < securityK; ++i) {
								sharedRand0[i].nextBytes(t0);
								sharedRand1[i].nextBytes(t1);
								BigInteger toSend = new BigInteger(t0);
								toSend = toSend.add(new BigInteger(t1).negate());
								toSend = toSend.add(x).mod(new BigInteger("2").pow(securityK));
								channel.send(toSend);

								share = share.add((new BigInteger(t0)).negate().shiftLeft(i)).mod(new BigInteger("2").pow(securityK));
						}
						result.add(share);
				}

        for (BigInteger x : result)  {
            System.out.println(x);
        }
				return result;
		}
};
