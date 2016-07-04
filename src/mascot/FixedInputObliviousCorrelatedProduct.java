package mascot;

import java.util.Arrays;
import java.util.ArrayList;
import java.math.BigInteger;
import java.io.IOException;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.nio.ByteBuffer;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class FixedInputObliviousCorrelatedProduct {
		private BigInteger delta;
    private int securityK;
		private ArrayList<byte[]> seeds;
		// WARNING: This is a stop-gap solution only. Use a
		// cryptographically strong generator in production.
    private Random[] sharedRand;
		
		public FixedInputObliviousCorrelatedProduct (String ipAddr, int port, BigInteger a_delta, int a_securityK) {
				delta = a_delta;
        securityK = a_securityK;
        sharedRand = new Random[securityK];
				OTExtensionMaliciousReceiver ot = new OTExtensionMaliciousReceiver(ipAddr,
																																					 port,
																																					 securityK);
				// Split bits in delta into different bytes to put in the OT
				// function call.
				if (delta.bitLength() > securityK)
						throw new RuntimeException("Delta too long. Expected securityK bits.");
				byte[] delta_split = new byte[securityK];
				for (int i = 0; i < securityK; ++i) {
						delta_split[i] = (delta.testBit(i))?(byte)1:(byte)0;//(byte)((delta[i / 8] >> (i % 8)) & 1);
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
						if (i % (securityK / 8) == (securityK / 8 - 1)) {
								seeds.add(number);
                sharedRand[i * 8 / securityK] = new Random(ByteBuffer.wrap(number).getLong());
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
		public ArrayList<BigInteger> extend(int numShares, Channel channel) throws IOException {
        ArrayList<BigInteger> result = new ArrayList<BigInteger>();
        // Iterate through every share
        for (int i = 0; i < numShares; ++i) {
            // We shall construct this share as we go
            BigInteger share = new BigInteger("0") ;
            // Iterate through components of a share
            for (int j = 0; j < securityK; ++j) {
                BigInteger ui;
                try {
                    ui = (BigInteger)channel.receive();
                }
                catch (ClassNotFoundException e) {
                    throw new RuntimeException("Error: Unexpected datatype recieved from other party.");
                }
                if (ui.bitLength() > securityK)
										throw new RuntimeException("Error: Unexpected length of share recieved from other party: " + ui.bitLength());

                // Compute the component
                byte[] bComponent = new byte[securityK / 8];
                sharedRand[j].nextBytes(bComponent);
								BigInteger component = new BigInteger(bComponent);
								if (delta.testBit(j))
										component = component.add(ui);
								component = component.shiftLeft(j);
								share = share.add(component).mod(new BigInteger("2").pow(securityK));
            }
            result.add(share.mod(new BigInteger("2").pow(securityK)));
        }

        for (BigInteger x : result)  {
						System.out.println(x);
        }
        return result;
		}
};
