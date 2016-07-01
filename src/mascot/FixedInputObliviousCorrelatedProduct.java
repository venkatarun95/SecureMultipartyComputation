package mascot;

import java.util.Arrays;
import java.util.ArrayList;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class FixedInputObliviousCorrelatedProduct {
		private Channel channel;
		private byte[] delta;
		private ArrayList<byte[]> seeds;
		
		public FixedInputObliviousCorrelatedProduct (String ipAddr, int port, Channel a_channel, byte[] a_delta, int securityK) {
				channel = a_channel;
				delta = a_delta;
				OTExtensionMaliciousReceiver ot = new OTExtensionMaliciousReceiver(ipAddr,
																																					 port,
																																					 8 * delta.length);
				// Split bits in delta into different bytes to put in the OT
				// function call.
				byte[] delta_split = new byte[delta.length * 8];
				for (int i = 0; i < 8 * delta.length; ++i) {
						delta_split[i] = (byte)((delta[i / 8] >> (i % 8)) & 1);
				}

				// Do the OTs
				OTBatchROutput outputs = ot.transfer(null, new OTExtensionGeneralRInput(delta_split, securityK));

				// Split `outputs` into the various received numbers
				if (!(outputs instanceof OTOnByteArrayROutput))
						throw new RuntimeException("Unexpected batch OT result received.");
				OTOnByteArrayROutput output = (OTOnByteArrayROutput)outputs;

				seeds = new ArrayList<byte[]>();
				byte[] number = new byte[securityK / 8];;
				for (int i = 0; i < output.getXSigma().length; ++i) {
						number[i % (securityK / 8)] = output.getXSigma()[i];
						if (i % (securityK / 8) == (securityK / 8 - 1) && i != 0) {
								seeds.add(number);
								number = new byte[securityK / 8];
						}
				}
				// for (byte[] x : seeds) {
				// 		for (byte y : x)
				// 				System.out.print(y + " ");
				// 		System.out.print("\n");
				// }
				ot.releaseResources();
		}

		public void Extend(int numShares) {
		}
};
