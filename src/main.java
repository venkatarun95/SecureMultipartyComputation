import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.exceptions.DuplicatePartyException;

import pederson.PedersonComm;
import pederson.PedersonShare;

public class main {
		public static void main(String[] args) throws IOException{
				if (args.length != 1) {
						System.err.println("Argument: <player.properties>");
						return;
				}

				// Setup communication
				LoadSocketParties loadParties = new LoadSocketParties(args[0]);
				List<PartyData> partiesList = loadParties.getPartiesList();
				SocketPartyData[] parties = partiesList.toArray(new SocketPartyData[0]);
				
				SocketMultipartyCommunicationSetup commSetup = new SocketMultipartyCommunicationSetup(partiesList);
				long timeoutInMs = 60000;  //The maximum amount of time we are willing to wait to set a connection.
				HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
				for (int i = 1; i < parties.length; ++i)
						connectionsPerParty.put(parties[i], 2);
				
				Map<PartyData, Map<String, Channel>> connections;
				try {
				    connections = commSetup.prepareForCommunication(connectionsPerParty, timeoutInMs);
				}
				catch (TimeoutException e) {
				 		System.err.println("Error: Timed out. Could not establish connection.");
				 		return;
				}

				// Create channels array
				SocketPartyData thisParty = parties[0];
				Arrays.sort(parties, new Comparator<SocketPartyData>() {
								@Override
								public int compare(SocketPartyData o1, SocketPartyData o2) {
										return o1.compareTo(o2);
								}
						});
				Channel[] channels = new Channel[parties.length];
				for (int i = 0; i < parties.length; ++i) {
						if (parties[i] == thisParty) {
								channels[i] = null;
								continue;
						}
						channels[i] = connections.get(parties[i]).values().iterator().next();
				}

				// Test linear operations
				// First player shares a number
				PedersonShare val1, val2;
				if (channels[0] == null) {
						PedersonShare[] shares = PedersonShare.shareValue(new BigInteger("10"), 2, parties.length);
						val1 = shares[0];
						PedersonComm.shareSender(shares, channels);
				}
				else {
						val1 = PedersonComm.shareReceiver(0, channels);
				}

				// Second player shares a value
				if (channels[1] == null) {
						PedersonShare[] shares = PedersonShare.shareValue(new BigInteger("21"), 2, parties.length);
						val2 = shares[1];
						PedersonComm.shareSender(shares, channels);
				}
				else { 
						val2 = PedersonComm.shareReceiver(1, channels);
				}

				// Compute an operation and open share
				PedersonShare res = val1.add(val2.constMultiply(new BigInteger("11")));

				System.out.println(PedersonComm.combineShares(res, 2, channels));

				// Now multiply two values and open share
				PedersonShare mult = PedersonComm.multiply(val1, res, channels);
				
				System.out.println("Product: " + PedersonComm.combineShares(mult, 2, channels) + " : ");
		}
}
