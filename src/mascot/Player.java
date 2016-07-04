package mascot;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.math.BigInteger;

import java.io.IOException;
import java.util.concurrent.TimeoutException;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.exceptions.DuplicatePartyException;

import org.bouncycastle.util.BigIntegers;

import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.dlog.GroupElement;
import edu.biu.scapi.primitives.dlog.openSSL.OpenSSLDlogECF2m;

import mascot.ChangingInputObliviousCorrelatedProduct;
import mascot.FixedInputObliviousCorrelatedProduct;

public class Player {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
				if (args.length != 1) {
						System.err.println("Usage: java Player <player.properties>");
						return;
				}

				// Setup communication
				LoadSocketParties loadParties = new LoadSocketParties(args[0]);
				List<PartyData> parties = loadParties.getPartiesList();

				SocketMultipartyCommunicationSetup commSetup = new SocketMultipartyCommunicationSetup(parties);
				long timeoutInMs = 60000;  //The maximum amount of time we are willing to wait to set a connection.
				HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
				connectionsPerParty.put(parties.get(1), 2);
				
				Map<PartyData, Map<String, Channel>> connections; // = commSetup.prepareForCommunication(connectionsPerParty, timeoutInMs);
				try {
				    connections = commSetup.prepareForCommunication(connectionsPerParty, timeoutInMs);
				}
				catch (TimeoutException e) {
				 		System.err.println("Error: Timed out. Could not establish connection.");
				 		return;
				}


				// Test Communication
				Channel testC = connections.get(parties.get(1)).values().iterator().next();
				testC.send("Hello World!!");;
				//String recv =  testC.receive();
				System.out.println(testC.receive());

				// Test Correlated Product OT
				int otherParty = 0;
				if (((SocketPartyData)parties.get(0)).getPort() == 8000)
						otherParty = 1;
				if (otherParty == 0) {
						ChangingInputObliviousCorrelatedProduct changingOT = new ChangingInputObliviousCorrelatedProduct("127.0.0.1", 8889, 64);
            ArrayList<BigInteger> xs = new ArrayList<BigInteger>();
            xs.add(new BigInteger("45"));
						xs.add(new BigInteger("3"));
						xs.add(new BigInteger("100"));
            changingOT.extend(xs, testC);
				}
				else {
						FixedInputObliviousCorrelatedProduct fixedOT = new FixedInputObliviousCorrelatedProduct("127.0.0.1", 8889, new BigInteger("278"), 64);
            fixedOT.extend(3, testC);
				}
    }
}

