package mascot;

//import java.util.Array;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.ArrayList;
import java.security.SecureRandom;

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
		private SecureRandom[] sharedRand0, sharedRand1;

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
				sharedRand0 = new SecureRandom[securityK / 8];
				sharedRand1 = new SecureRandom[securityK / 8];

				// Select random seeds
				SecureRandom random = new SecureRandom();
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
						if (i % (securityK / 8) == securityK / 8 - 1 && i > 0) {
								seeds0.add(tempSeed0);
								seeds1.add(tempSeed1);
								sharedRand0[i / 8] = new SecureRandom(tempSeed0));
								sharedRand1[i / 8] = new SecureRandom(tempSeed1));
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
		 * @return List of shares. Each share is a securityK sized vector
		 * of securityK bit values.
		 */
		public ArrayList<byte[][]> Extend(ArrayList<byte[]> xList, Channel channel) {
				ArrayList<byte[]> result = new ArrayList<byte[]>();
				for (byte[] x : xList) {
						if (x.length != SecurityK / 8)
								throw new RuntimeException("Incorrect length of x_i. Expecting securityK bits");
						byte[] t0 = new byte[securityK / 8], t1 = new byte[securityK / 8];
						byte[] toSend = new byte[securityK];
						byte[][] t = new byte[securityK][securityK];
						for (int i = 0; i < securityK; ++i) {
								sharedRand0[i].nextBytes(t0);
								sharedRand1[i].nextBytes(t1);
								result.add(t0);
								for (int i = 0; i < securityK / 8; ++i)
										toSend[i] = t0[i] - t1[i] + x[i];
								channel.send(toSend);
						}
						
				}
		}
};
