package pederson;

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
import pederson.ClearTextProxy;

public class Test {
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
				int thisPartyId = -1;
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
								thisPartyId = i;
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
				PedersonShare resShare = val1.add(val2.constMultiply(new BigInteger("11")));
        BigInteger res = PedersonComm.combineShares(resShare, channels);
        if (res.intValue() != 241)
            throw new RuntimeException("Error in linear operations. Test failed.");

				// Now multiply two values and open share
				PedersonShare mult = PedersonComm.multiply(val1, resShare, channels);
				if (PedersonComm.combineShares(mult, channels).intValue() != 2410)
            throw new RuntimeException("Error in multiplication. Test Failed.");
				
        // Share a random value and open it
        PedersonShare randValShare = PedersonComm.shareRandomNumber(2, channels);
        BigInteger randVal = PedersonComm.combineShares(randValShare, channels);

				// Check plaintext exponentiation
        BigInteger exponentiated = PedersonComm.plaintextExponentiate(BigInteger.valueOf(4), randValShare, channels);
        if (exponentiated.compareTo(BigInteger.valueOf(4).modPow(randVal, PedersonShare.mod)) != 0)
            throw new RuntimeException("Error in exponentiation. Result did not match what was expected.");

				// Test clear-text proxy generation.
				int ctpSecret = 10, ctpNumBits = 64;
				ClearTextProxy ctpGen = new ClearTextProxy(ctpNumBits, 2, channels);
				PedersonShare[] bitShared = new PedersonShare[ctpNumBits];
				for (int i = 0; i < ctpNumBits; ++i)
						bitShared[i] = PedersonShare.shareConstValue(BigInteger.valueOf(((ctpSecret & (1 << i)) > 0)?1:0),
																											2, 5)[thisPartyId];
				BigInteger ctpResult = ctpGen.generateCtp(bitShared, channels);

				// Compute what clear-text proxy should be
				BigInteger expectedCtp = PedersonComm.combineShares(ctpGen.randomKey[0], channels);
				for (int i = 0; i < ctpNumBits; ++i) {
						BigInteger randomKey = PedersonComm.combineShares(ctpGen.randomKey[i + 1], channels);
						if ((ctpSecret & (1 << i)) != 0)
								expectedCtp = expectedCtp.multiply(randomKey).mod(PedersonShare.modQ);
				}
				expectedCtp = PedersonShare.genVerif.modPow(expectedCtp, PedersonShare.mod);
				
				if (expectedCtp.compareTo(ctpResult) != 0)
						throw new RuntimeException("Generated clear-text proxy is not what was expected");

				System.out.println("Tests Finished Successfully!");
		}
}