package pederson;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.security.SecureRandom;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.exceptions.DuplicatePartyException;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import mpcCrypto.BonehBoyenSign;
import mpcCrypto.PRF;

public class Profile {
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
				int index = -1;
				for (int i = 0; i < channels.length; ++i) {
						if (channels[i] == null) {
								index = i;
								break;
						}
				}

				PRF prf = new PRF(3, channels);
				PedersonShare val = PedersonShare.shareConstValue(BigInteger.valueOf(10), 3, 5)[index];
				BonehBoyenSign sign = new BonehBoyenSign(3, channels);
				PedersonShare msg = PedersonShare.shareConstValue(BigInteger.valueOf(10), 3, 5)[index];
				
				long startTime = System.nanoTime();    

				for (int i = 0; i < 100; ++i) {
						Element res = prf.compute(val);
						if (i % 10 == 0)
								System.out.println(i);
				}

				// for (int i = 0; i < 10; ++i) {
				// 		sign.compute(msg);
				// 		if (i % 10 == 0)
				// 				System.out.println(i);
				// }

				long estimatedTime = System.nanoTime() - startTime;
				System.out.println("Time elapsed: " + estimatedTime);
		}
}

/*
 * For PRF evaluation
 * - 5 players, 4 cores, 100 PRF computations, type 'a' -> G1 took 5min57s (real time) and 4m10s (user time)
 * - 5 players, 4 cores, 100 PRF computations, type 'a' -> GT took 1min37s (real time) 0m32s (user time) and 86s (in-program measurement)
 *
 * For Boneh-Boyen Signatures
 * - 5 Players, 4 cores, 10 signatures, type 'a' -> G1 took 1m10s (real time), 0m48s (user time) and 57s (in-program measurement)
 */
