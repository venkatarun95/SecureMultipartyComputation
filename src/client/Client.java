package client;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.SecureRandom;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.*;

import pederson.PedersonShare;
import pederson.PedersonComm;

public class Client {
    private static SecureRandom random = new SecureRandom();

    private static Socket[] serverSockets;
    private static ObjectInputStream[] inStreams;
    private static ObjectOutputStream[] outStreams;
    private static int numServers;

    public static void main(String[] args) {
				if (args.length != 1) {
						System.out.println("Arguments: [serverIp:port::...]");
						return;
				}

        connectToServers(args[0]);
        System.out.println("Connected to servers.");

        try {
            register(5);
				}
        catch (IOException|ClassNotFoundException e) {
            System.err.println("Error while communicating with server.\n" + e.getMessage());
        }
		}

    private static void connectToServers(String addrString) {
				String[] addresses = addrString.split("::");
				String[] serverIps = new String[addresses.length];
				int[] serverPorts = new int[addresses.length];
				for (int i = 0; i < addresses.length; ++i) {
						serverIps[i] = addresses[i].split(":")[0];
						serverPorts[i] = Integer.parseInt(addresses[i].split(":")[1]);
				}

				serverSockets = new Socket[addresses.length];
				inStreams = new ObjectInputStream[addresses.length];
				outStreams = new ObjectOutputStream[addresses.length];
				for (int i = 0; i < addresses.length; ++i) {
						try {
								serverSockets[i] = new Socket(serverIps[i], serverPorts[i]);
								outStreams[i] = new ObjectOutputStream(serverSockets[i].getOutputStream());
								inStreams[i] = new ObjectInputStream(serverSockets[i].getInputStream());
						}
						catch (IOException e) { // TODO: be more specific
								System.err.println("Error while establishing connection with server. " + e.getMessage());
								System.exit(1);
						}
        }
        numServers = addresses.length;
    }

    private static void register(int numTickets) throws IOException,ClassNotFoundException {
        // Choose our identity
        BigInteger identity = new BigInteger(64, random);

        // Choose keys
        BigInteger[] tickets = new BigInteger[numTickets];
        PedersonShare[][] ticketsShares = new PedersonShare[numTickets][];
        for (int i = 0; i < numTickets; ++i) {
            tickets[i] = new BigInteger(64, random);
            ticketsShares[i] = PedersonShare.shareValue(tickets[i], numServers/2, numServers);
        }

        // Send to servers
        for (int i = 0; i < numServers; ++i) {
            int serverIndex = (int)inStreams[i].readObject();
            System.out.println(serverIndex);
            outStreams[i].writeObject(new String("Register"));
            outStreams[i].writeObject(identity);
            outStreams[i].writeObject(numTickets);
            for (int j = 0; j < numTickets; ++j)
                outStreams[i].writeObject(ticketsShares[j][serverIndex]);
            outStreams[i].flush();
        }

        // Receive MACs from servers
        byte[][] ticketMacs = new byte[numTickets][];
        for (int t = 0; t < numTickets; ++t) {
            // Receive exponentiated shares
            Element[][] expShares = new Element[numServers][];
            for (int i = 0; i < numServers; ++i) {
                byte[][] expShareBytes = (byte[][])inStreams[i].readObject();
                expShares[i] = new Element[expShareBytes.length];
                for (int j = 0; j < expShareBytes.length; ++j) {
                    expShares[i][j] = PedersonShare.group.newOneElement();
                    expShares[i][j].setFromBytes(expShareBytes[j]);
                }
            }
            Element mac = PedersonComm.plaintextExponentiateRecv(expShares, numServers / 2, numServers);
            ticketMacs[t] = mac.toBytes();
        }
    }
}
