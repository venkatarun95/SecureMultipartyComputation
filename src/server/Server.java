package server;

import java.io.IOException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.*;
import java.util.*;
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
    // A fixed id assigned to each escrow. Important for proper MPC functioning
    //
    // It is initially set by an ordering on IP address and port number. After
    // setup it is permanently stored in a database.
    static int thisPartyId;

    // Database variables
    static Connection dbConnect;
    static Statement dbStatement;

    // Crypto variables
    static PRF idMacPRF;
    static PRF idRevealPRF;

		public static void main(String[] args) {
				if (args.length != 4) {
						System.out.println("Arguments: port player.properties mysqlPath dbname");
            return;
        }

        connectToPeers(args[1]);

        try {
            connectToDB(args[2], args[3]);
        }
        catch(Exception e) {
            System.out.println("Error connecting to database. " + e.getMessage());
            return;
        }

				int serverPort = Integer.parseInt(args[0]);

				ServerSocket serverSocket;
				try {
						serverSocket = new ServerSocket(serverPort);
				}
				catch (Exception e) { // TODO: be more specific
						System.err.println("Error: Could not bind to port " + serverPort);
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
                        Element[] result = idMacPRF.computeSend(value, channels);
                        byte[][] resBytes = new byte[result.length][];
                        for (int j = 0; j < result.length; ++j)
                            resBytes[j] = result[j].toBytes();
                        outStream.writeObject(resBytes);
                        outStream.flush();

                        Element reveal = idRevealPRF.compute(value, channels);
                        dbStatement.executeUpdate("INSERT INTO Identities(identity, revealKey) VALUES('"
                                                  + encodeToBase64(identity) + "', '"
                                                  + encodeToBase64(reveal.toBytes()) + "')");
                    }
                }
                else if(action.equals("Allege")) {
                    PedersonShare ticketShare = (PedersonShare)inStream.readObject();
                    Element claimedMac = PedersonShare.group.newOneElement();
                    claimedMac.setFromBytes((byte[])inStream.readObject());
                    PedersonShare metaDataShare = (PedersonShare)inStream.readObject();
                    int revealThreshold = (int)inStream.readObject();

                    // Calculate mac and verify claimedMac is correct
                    Element mac = idMacPRF.compute(ticketShare, channels);
                    boolean identityVerified = mac.isEqual(claimedMac);

                    // Verify that this ticket hasn't been used before
                    ResultSet numMatchingTickets = dbStatement.executeQuery("SELECT count(identifier) FROM Allegations WHERE identifier='"
                                                                            + encodeToBase64(mac.toBytes()) + "'");
                    numMatchingTickets.next();
                    if (numMatchingTickets.getInt("count(identifier)") > 0) {
                        identityVerified = false;
                        System.out.println("Client tried to re-use tickets.");
                    }

                    // Send result of verification to client
                    outStream.writeObject(identityVerified);
                    outStream.flush();
                    if (!identityVerified)
                        continue;

                    // Do the bucketing
                    PRF bucket = getBucket(revealThreshold);
                    Element prf = bucket.compute(metaDataShare, channels);
                    ResultSet matching = dbStatement.executeQuery("SELECT identifier FROM Allegations WHERE prf='"
                                                                  + encodeToBase64(prf.toBytes())
                                                                  + "' AND bucket=" + (revealThreshold-1));
                    dbStatement.executeUpdate("INSERT INTO Allegations(identifier, bucket, prf, threshold) VALUES('"
                                              + encodeToBase64(mac.toBytes())
                                              + "', '" + encodeToBase64(prf.toBytes())
                                              + "', " + (revealThreshold-1)
                                              + ", " + revealThreshold + ")");
                    if (!matching.first())
                        continue; // No matches. Bucketing algorithm ends

                    // Navigate to the bottom-most bucket that has these allegations
                    int curBucket = revealThreshold-1;
                    String collId = matching.getString("identifier"); // Identifier of an allegation in the matching collection
                    String collPRF; // PRF of the collection in the current bucket
                    while (true) {
                        ResultSet nextMatching = dbStatement.executeQuery("SELECT prf FROM Allegations WHERE identifier='"
                                                            + collId
                                                            + "' AND bucket=" + curBucket);
                        nextMatching.next();
                        collPRF = nextMatching.getString("prf");
                        if (matching.first()) {
                            -- curBucket;
                            dbStatement.executeUpdate("INSERT INTO Allegations(identifier, bucket, prf, threshold) VALUES('"
                                                      + encodeToBase64(mac.toBytes())
                                                      + "', '" + collPRF
                                                      + "', " + curBucket
                                                      + ", " + revealThreshold + ")");
                        }
                        else
                            break;
                    }

                    // See if we can go down further
                    while (true) {
                        ResultSet collectionSizeRes = dbStatement.executeQuery("SELECT count(identifier), min(threshold) FROM Allegations WHERE prf='"
                                                                               + collPRF + "' AND bucket='" + curBucket + "'");
                        collectionSizeRes.first();
                        int collectionSize = collectionSizeRes.getInt("count(identifier)");
                        int minThreshold = collectionSizeRes.getInt("min(threshold)");
                        if (minThreshold >= curBucket + collectionSize)
                            break;
                        -- curBucket;
                        // TODO(venkat): insert into next bucket
                    }
                }
                else {
                    System.err.println("Unrecognized command '" + action +"'.");
                    continue;
                }
            }
						catch (IOException|ClassNotFoundException|SQLException e) {
								System.err.println("Error while communicating with client.\n" + e.getMessage());
						}
				}
		}

    /**
     * Returns a PRF object corresponding to bucket with given threshold.
     *
     * Loads bucket from the database if available, else creates a new one.
     *
     * Warning: The current implementation doesn't use MySQL transactions, so it
     * is possible for two threads to independently create the same bucket.
     */
    private static PRF getBucket(int threshold) throws SQLException,IOException,ClassNotFoundException {
        PRF result;
        ResultSet buckets = dbStatement.executeQuery("SELECT prf FROM Buckets WHERE threshold=" + threshold);
        if (!buckets.first()) {
            // Create bucket
            result = new PRF(channels.length / 2, channels);
            dbStatement.executeUpdate("INSERT INTO Buckets(threshold, prf) VALUES(" + threshold + ", '" + encodeToBase64(result) + "')");
        }
        else
            // Read bucket from DB
            result = (PRF)decodeFromBase64(buckets.getString("prf"));
        return result;
    }

    private static Object decodeFromBase64(String str) throws IOException,ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(str);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object result = ois.readObject();
        ois.close();
        return result;
    }

    private static String encodeToBase64(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        try {
            oos.writeObject(obj);
        }
        catch (Exception e) {
            throw new RuntimeException("Could not serialize object. " + e.getMessage());
        }
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /** Load properties file and connect to specified peers. Populates
     * <code>channels</code>.
     */
		private static void connectToPeers(String propertiesFileName) {
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

    /**
     * Connects to MySQL database. If not already present, creates database and
     * some tables which are populated with appropriate initial values.
     */
    private static void connectToDB(String address, String dbname) throws SQLException,IOException,ClassNotFoundException {
        //Class.forName("com.mysql.jdbc.Driver");
        dbConnect = DriverManager.getConnection(address);
        dbStatement = dbConnect.createStatement();

        // Use database if present. Else create
        ResultSet databases = dbStatement.executeQuery("SHOW DATABASES");
        boolean databaseExists = false;
        while (databases.next()) {
            if(databases.getString("Database").equals(dbname)) {
                databaseExists = true;
                break;
            }
        }
        if (!databaseExists)
            dbStatement.executeUpdate("CREATE DATABASE " + dbname);
        dbStatement.executeUpdate("USE " + dbname);
        databases.close();

        // If config table doesn't exist, create it. Else read configs
        ResultSet tables = dbStatement.executeQuery("SHOW TABLES");
        boolean configTableExists = false;
        while (tables.next()) {
            if (tables.getString("Tables_in_" + dbname).equals("Config")) {
                configTableExists = true;
                ResultSet configTable = dbStatement.executeQuery("SELECT name, intVal, charVal FROM Config");
                thisPartyId = -1;
                idMacPRF = idRevealPRF = null;

                System.out.println("Reading configs from database");
                while (configTable.next()) {
                    if (configTable.getString("name").equals("thisPartyId"))
                        thisPartyId = configTable.getInt("intVal");
                    else if (configTable.getString("name").equals("idMacPRF"))
                        idMacPRF = (PRF)decodeFromBase64(configTable.getString("charVal"));
                    else if (configTable.getString("name").equals("idRevealPRF"))
                        idRevealPRF = (PRF)decodeFromBase64(configTable.getString("charVal"));
                    else
                        System.err.println("Unrecognized config row '" + configTable.getString("name"));
                }
                if (thisPartyId == -1)
                    throw new RuntimeException("Could not load 'thisPartyId' from config table.");
                break;
            }
        }
        if (!configTableExists) {
            System.out.println("Initializing database");
            idMacPRF = new PRF(channels.length / 2, channels);
            idRevealPRF = new PRF(channels.length / 2, channels);

            dbStatement.executeUpdate("CREATE TABLE Config(name CHAR(20) PRIMARY KEY, intVal INT, charVal VARCHAR(4000))");
            dbStatement.executeUpdate("INSERT INTO Config(name, intVal) VALUES('thisPartyId', '" + thisPartyId + "')");
            dbStatement.executeUpdate("INSERT INTO Config(name, charVal) VALUES('idMacPRF', '" + encodeToBase64(idMacPRF) + "')");
            dbStatement.executeUpdate("INSERT INTO Config(name, charVal) VALUES('idRevealPRF', '" + encodeToBase64(idRevealPRF) + "')");

            dbStatement.executeUpdate("CREATE TABLE Buckets(threshold INT PRIMARY KEY, prf VARCHAR(4000))");
            dbStatement.executeUpdate("CREATE TABLE Identities(identity VARCHAR(4000), revealKey VARCHAR(4000))");
            dbStatement.executeUpdate("CREATE TABLE Allegations(identifier VARCHAR(3072) PRIMARY KEY, prf VARCHAR(4000), bucket INT, threshold INT)");
        }
    }
}
