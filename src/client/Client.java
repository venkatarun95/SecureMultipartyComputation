package client;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.*;

import pederson.PedersonShare;
import pederson.PedersonComm;

public class Client {
    public static void main(String[] args) {
				if (args.length != 1) {
						System.out.println("Arguments: [serverIp:port::...]");
						return;
				}
				String[] addresses = args[0].split("::");
				String[] serverIps = new String[addresses.length];
				int[] serverPorts = new int[addresses.length];
				for (int i = 0; i < addresses.length; ++i) {
						serverIps[i] = addresses[i].split(":")[0];
						serverPorts[i] = Integer.parseInt(addresses[i].split(":")[1]);
				}

				Socket[] serverSockets = new Socket[addresses.length];

				ObjectInputStream[] inStreams = new ObjectInputStream[addresses.length];
				ObjectOutputStream[] outStreams = new ObjectOutputStream[addresses.length];
				for (int i = 0; i < addresses.length; ++i) {
						try {
                System.out.println("Connecting to " + serverIps[i] + " " + serverPorts[i]);
								serverSockets[i] = new Socket(serverIps[i], serverPorts[i]);
								outStreams[i] = new ObjectOutputStream(serverSockets[i].getOutputStream());
								inStreams[i] = new ObjectInputStream(serverSockets[i].getInputStream());
						}
						catch (Exception e) { // TODO: be more specific
								System.err.println("Error while establishing connection with server. " + e.getMessage());
								return;
						}
        }

        try {
            PedersonShare[] shares = PedersonShare.shareValue(BigInteger.valueOf(10), addresses.length / 2, addresses.length);
            // Send shares
            for (int i = 0; i < addresses.length; ++i) {
								outStreams[i].writeObject(shares[i]);
								outStreams[i].flush();
						}

            // Receive exponentiated shares
            Element[][] expShares = new Element[addresses.length][];
            for (int i = 0; i < addresses.length; ++i) {
                byte[][] expShareBytes = (byte[][])inStreams[i].readObject();
                expShares[i] = new Element[expShareBytes.length];
                for (int j = 0; j < expShareBytes.length; ++j) {
                    expShares[i][j] = PedersonShare.group.newOneElement();
                    expShares[i][j].setFromBytes(expShareBytes[j]);
                }

            }
            PedersonComm.plaintextExponentiateRecv(expShares, addresses.length / 2, addresses.length);
				}
        catch (IOException|ClassNotFoundException e) {
            System.err.println("Error while communicating with server.\n" + e.getMessage());
        }
		}
}
