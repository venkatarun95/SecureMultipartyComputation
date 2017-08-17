package server;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import java.math.BigInteger;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
import edu.biu.scapi.comm.twoPartyComm.PartyData;
import edu.biu.scapi.comm.twoPartyComm.SocketPartyData;
import edu.biu.scapi.exceptions.DuplicatePartyException;
import it.unisa.dia.gas.jpbc.*;

import pederson.PedersonShare;
import pederson.PedersonComm;

import mpcCrypto.PRF;

public class Server {
		static Channel[] channels;
    static int thisPartyId;

		public static void main(String[] args) {
				if (args.length != 2)
						System.out.println("Arguments: port player.properties>");

				connectToPeers(args[1]);

				int serverPort = Integer.parseInt(args[0]);

				ServerSocket serverSocket;
				try {
						serverSocket = new ServerSocket(serverPort);
				}
				catch (Exception e) { // TODO: be more specific
						System.err.println("Error: Could not bind to port " + serverPort);
						return;
				}

        PRF bucket;
        try {
            bucket = new PRF(channels.length / 2, channels);
        }
        catch (IOException e) {
            System.err.println("Communication error while setting up bucket.");
            return;
        }
        System.out.println("Server setup complete. Waiting for clients.");

				while (true) {
						ObjectInputStream inStream;
						ObjectOutputStream outStream;
						try {
								Socket clientSocket = serverSocket.accept();
								inStream = new ObjectInputStream(clientSocket.getInputStream());
								outStream = new ObjectOutputStream(clientSocket.getOutputStream());
						}
						catch (Exception e) { // TODO: be more specific
								System.err.println("Error while establishing connection with client.");
								continue;
						}

						try {
                outStream.writeObject(thisPartyId);
                outStream.flush();
                String action = (String)inStream.readObject();
                if (action.equals("Register")) {
                    BigInteger identity = (BigInteger)inStream.readObject();
                    int numTickets = (int)inStream.readObject();
                    for (int i = 0; i < numTickets; ++i) {
                        PedersonShare value = (PedersonShare)inStream.readObject();
                        System.out.println("Got value from client");
                        Element[] result = bucket.computeSend(value);
                        byte[][] resBytes = new byte[result.length][];
                        for (int j = 0; j < result.length; ++j)
                            resBytes[j] = result[j].toBytes();
                        outStream.writeObject(resBytes);
                        outStream.flush();

                        Element auxResult = bucket.compute(value);
                    }
                }
                else if(action.equals("Allege")) {
                    PedersonShare ticketShare = (PedersonShare)inStream.readObject();
                    Element claimedMac = PedersonShare.group.newOneElement();
                    claimedMac.setFromBytes((byte[])inStream.readObject());
                    int revealThreshold = (int)inStream.readObject();

                    Element mac = bucket.compute(ticketShare);
                    if (mac.isEqual(claimedMac))
                        outStream.writeObject(true);
                    else
                        outStream.writeObject(false);
                    outStream.flush();
                }
                else {
                    System.err.println("Unrecognized command '" + action +"'.");
                    continue;
                }
            }
						catch (IOException|ClassNotFoundException e) {
								System.err.println("Error while communicating with client.\n" + e.getMessage());
						}
				}
		}

		public static void connectToPeers(String propertiesFileName) {
				// Setup communication
				LoadSocketParties loadParties = new LoadSocketParties(propertiesFileName);
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
				thisPartyId = -1;
				Arrays.sort(parties, new Comparator<SocketPartyData>() {
								@Override
								public int compare(SocketPartyData o1, SocketPartyData o2) {
										return o1.compareTo(o2);
								}
						});
				channels = new Channel[parties.length];
				for (int i = 0; i < parties.length; ++i) {
						if (parties[i] == thisParty) {
								channels[i] = null;
								thisPartyId = i;
								continue;
						}
						channels[i] = connections.get(parties[i]).values().iterator().next();
				}
		}
}
