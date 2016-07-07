package mascot;

import java.util.Arrays;

import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.OTOnByteArrayROutput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionGeneralRInput;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTExtensionMaliciousReceiver;

public class MultiplicationTripleSubProtocolReceiver {
		BigInteger[] a, b;
		int securityK;
		OTExtensionMaliciousReceiver ot;
		
		/**
		 * Subprotocol to help compute multiplication triples by
		 * interacting with MultiplicationTripleSubProtocolSender on the
		 * other side.<P>
		 *
		 * Constructor initializes a few things so that `run` can function
		 * efficiently each time it is called.
		 */
		public MultiplicationTripleSubProtocolReceiver(String ipAddr, int port, int a_securityK, BigInteger[] a_a, BigInteger[] a_b) {
				securityK = a_securityK;
				a = a_a;
				b = a_b;
				
				if (b.length != securityK / 8)
						throw new RuntimeException("b should have securityK bits.");
				if ((a.length * 8) % securityK != 0)
						throw new RuntimeException("a's length should be a multiple of securityK");
				if (securityK < 64 || (securityK  == 64 && 8 * a.length / securityK < 4) || (securityK >= 128 && 8 * a.length / securityK < 3))
						throw new RuntimeException("Insufficient security parameters.");

				ot = new OTExtensionMaliciousReceiver(ipAddr,
																							port,
																							securityK);
		}

		public void run() {
				byte[] a_split = new byte[a.length * 8];
				for (int i = 0; i < a.length * 8; ++i)
						a_split[i] = (a.testBit(i))?(byte)1:(byte)0;

				OTBatchROutput outputs = ot.transfer(null, new OTExtensionGeneralRInput(a_split, a.length));
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
		}

		protected void finalize() {
				// close() should be called as soon as object is done with so
				// that resources can be released ASAP. We should not wait for
				// finalize();
				close();
		}
		
		public void close() {
				ot.releaseResources();
		}
}
