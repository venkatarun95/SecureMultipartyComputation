package mascot;

import java.util.Arrays;
import java.util.ArrayList;
import java.io.IOException;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class FixedInputObliviousCorrelatedProduct {
		private byte[] delta;
    private int securityK;
		private ArrayList<byte[]> seeds;
    private SecureRandom[] sharedRand;
		
		public FixedInputObliviousCorrelatedProduct (String ipAddr, int port, byte[] a_delta, int a_securityK) {
				delta = a_delta;
        securityK = a_securityK;
        sharedRand = new SecureRandom[securityK];
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
                sharedRand[i * 8 / securityK] = new SecureRandom(number);
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

    /**
     *  Returns additive shares of x_i s.\Delta, where \Delta is the
     *  fixed input of this player<p>
     *
     *  Note: In the byte array, 0th index is treated as most
     *  significant byte.
     */
		public ArrayList<byte[]> extend(int numShares, Channel channel) throws IOException {
        ArrayList<byte[]> result = new ArrayList<byte[]>();
        // Iterate through every share
        for (int i = 0; i < numShares; ++i) {
            // We shall construct this share as we go
            byte[] share = new byte[securityK];
            // Iterate through components of a share
            for (int j = 0; j < securityK; ++j) {
                byte[] ui;
                try {
                    ui = (byte[])channel.receive();
                }
                catch (ClassNotFoundException e) {
                    throw new RuntimeException("Error: Unexpected datatype recieved from other party.");
                }
                if (ui.length != securityK / 8)
                    throw new RuntimeException("Error: Unexpected length of share recieved from other party: " + ui.length);

                // Compute the component
                byte[] component = new byte[securityK / 8];
                sharedRand[j].nextBytes(component);
                if (delta[j / 8] & (1 << j) != 0) {
                    int carry = 0;
                    for (int k = securityK / 8 - 1; k >= 0; --k) {
                        if ((int)component[k] + ui[k] + carry > 255)
                            carry = 1;
                        else carry = 0;
                        component[k] += ui[k] + carry;
                    }
                }

                // Left shift component by j bits
                // First shift the bytes
                for (int k = 0; k < securityK / 8; ++k) {
                    if (k + j / 8 < securityK / 8)
                        component[k] = component[k + j / 8];
                    else
                        component[k] = 0;
                }
                // Now shift the bits
                for (int k = 0; k < securityK / 8; ++k) {
                    component[k] = (byte)(component[k] << (j % 8));
                    if (k + 1 < securityK / 8)
                        component[k] |= (byte)((component[k + 1] >> (8 - (j % 8)))
                                           & ((1 << (j % 8)) - 1));
                }

                // And the component to the share
                int carry = 0;
                for (int k = securityK / 8 - 1; k >= 0; --k) {
                    if ((int)component[k] + share[k] + carry > 255)
                        carry = 1;
                    else
                        carry = 0;
                    share[k] += component[k] + carry;
                }
            }
            result.add(share);
        }
        return result;
		}
};
