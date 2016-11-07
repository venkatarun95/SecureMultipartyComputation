package client;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;

import java.math.BigInteger;

import mpcCrypto.SchnorrSignature;
import mpcCrypto.SchnorrSignatureShare;

public class Client {
		public static void main(String[] args) {
				if (args.length != 3) {
						System.out.println("Arguments: [serverIp:port::...] secret pubKey");
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

				// Prepare the signature shares
				SchnorrSignatureShare[] signatureShares = SchnorrSignature.sign(BigInteger.valueOf(10),
												BigInteger.valueOf(878),
												true, 2, 5);
				
				ObjectInputStream[] inStreams = new ObjectInputStream[addresses.length];
				ObjectOutputStream[] outStreams = new ObjectOutputStream[addresses.length];
				for (int i = 0; i < addresses.length; ++i) {
						try {
								serverSockets[i] = new Socket(serverIps[i], serverPorts[i]);
								outStreams[i] = new ObjectOutputStream(serverSockets[i].getOutputStream());
								inStreams[i] = new ObjectInputStream(serverSockets[i].getInputStream());
						}
						catch (Exception e) { // TODO: be more specific
								System.err.println("Error while establishing connection with server.");
								return;
						}
				
						try {
								outStreams[i].writeObject(signatureShares[i]);
								outStreams[i].flush();
						}
						catch (IOException e) {
								System.err.println("Error while communicating with server.\n" + e.getMessage());
						}
				}
		}
}
