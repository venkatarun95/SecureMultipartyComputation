import json
import pickle
import random
import socket
import subprocess
import sys
import tempfile
import time

config = {
    "parallelism": 2,
    "this_addr": ("127.0.0.1", 8000),
    "other_addr": [("127.0.0.1", 8001), ("127.0.0.1", 8002)],
    'classpath': '../assets/Scapi-2.4.jar::../assets/commons-exec-1.2.jar:../assets/bcprov-jdk16-146.jar:../lib/hamcrest-core-1.3.jar:../assets/activemq-all-5.9.1.jar:../lib/jpbc-api-2.0.0.jar:../lib/jpbc-plaf-2.0.0.jar:/usr/share/java/mysql-connector-java.jar:../src',
    'lib_path': '../assets/:/usr/ssl/lib/',
}

# To be decided at run-time
# - id - uniquely identifies this server with a number between 0 and
#   num_servers-1
# - addrs - addresses of setup scripts in sorted order. Here,
#   addrs[id] is this_addr
# - sockets - sockets to other servers indexed by addr
# - replica_addrs - addresses of the replicas of this server
# - other_replica_addrs - addresses of the replicas of other servers
#   indexed by the addresses of their setup scripts
# - sql_addr - address of the MySQL server
# - dbname - name of the database in the server
params = {}

def sendstr(socket, msg):
    '''Send an entire string, to be received by recvstr'''
    socket.send(str(len(msg)).rjust(16, '0'))
    socket.sendall(msg)

def recvstr(socket):
    '''Receive the entire string sent by sendstr'''
    msglen = ''
    while len(msglen) < 16:
        msglen += socket.recv(16-len(msglen))
    msglen = int(msglen)
    msg = ''
    while len(msg) < msglen:
        msg += socket.recv(msglen - len(msg))
    return msg

def error_exit(msg=''):
    close_sockets()
    print("Fatal error. Exiting\n%s" % msg)
    exit(1)

def init_params():
    # Sort the addresses in lexicographic order to find id
    addrs = [config['this_addr']] + config['other_addr']
    addrs.sort()
    params['addrs'] = addrs
    params['id'] = addrs.index(config['this_addr'])
    # Pick some random ports. If any of them isn't available, setup will fail
    params['replica_addrs'] = [(config['this_addr'][0], random.randint(5000, 60000))
                                for x in range(config['parallelism'])]
    params['sql_addr'] = 'jdbc:mysql://localhost/?user=escrow%d&password=e%d&useSSL=false' % (
        params['id']+1, params['id'] + 1
    )
    params['db_name'] = 'escrow%d' % (params['id'] + 1)

def setup_sockets():
    '''Synchronize with setup scripts on other servers'''

    sockets = {}
    num_success_conns = 0
    listensocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listensocket.bind(config['this_addr'])
    listensocket.listen(2 * len(config['other_addr']))
    try:
        while params['id'] > num_success_conns:
            newsocket, newsocketaddr= listensocket.accept()
            other_addr = recvstr(newsocket)
            sockets[tuple(json.loads(other_addr))] = newsocket
            num_success_conns += 1
    except Exception as e:
        listensocket.close()
        error_exit("Error listening for connections from setup scripts\n%s" % e)

    assert(num_success_conns == params['id'])
    num_success_conns += 1
    time.sleep(2)
    try:
        while num_success_conns < len(params['addrs']):
            newsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            newsocket.connect(params['addrs'][num_success_conns])
            sendstr(newsocket, json.dumps(config['this_addr']))
            sockets[params['addrs'][num_success_conns]] = newsocket
            num_success_conns += 1
    except Exception as e:
        newsocket.close()
        error_exit("Error connecting to setup script at %s \n%s"
              % (str(params['addrs'][params['id']]), e))
    params['sockets'] = sockets

def exchange_params():
    # Send own params
    for addr in params['sockets']:
        sendstr(params['sockets'][addr], json.dumps({
            'id': params['id'],
            'addrs': params['addrs'],
            'replica_addrs': params['replica_addrs']
        }))

    # Receive and validate others' params
    params['other_replica_addrs'] = {}
    for addr in params['sockets']:
        other = json.loads(recvstr(params['sockets'][addr]))

        if len(other['addrs']) != len(params['addrs']):
            error_exit("Mismatched number of servers with %s" % str(addr))
        for i in range(len(other['addrs'])):
            if other['addrs'][i][0] != params['addrs'][i][0]\
               and other['addrs'][i][1] != params['addrs'][i][1]:
                print()
                print("Ours: %s" % str(params['addrs']))
                print("Theirs: %s" % str(other['addrs']))
                error_exit("Mismatched set of setup script addresses with %s\nOurs: %s\nTheirs: %s\n"
                           % (str(addr), str(params['addrs']), str(other['addrs'])))

        if len(other['replica_addrs']) != len(params['replica_addrs']):
            error_exit("Mismatched number of replicas with %s. Ours: %d, theirs: %d"
                  % (str(addr),
                     len(other['replica_addrs']),
                     len(params['replica_addrs'])))

        params['other_replica_addrs'][addr] = other['replica_addrs']

def start_servers():
    for replica in range(config['parallelism']):
        i = 0
        ips, ports = '', ''
        ips += "IP%d = %s\n" % (i, params['replica_addrs'][replica][0])
        ports += "Port%d = %d\n" % (i, params['replica_addrs'][replica][1])
        for peer in config['other_addr']:
            ips += "IP%d = %s\n" % (i+1, params['other_replica_addrs'][peer][replica][0])
            ports += "Port%d = %d\n" % (i+1, params['other_replica_addrs'][peer][replica][1])
            i += 1
        tfile = tempfile.NamedTemporaryFile(mode='w', delete=False)
        tfile.write("NumOfParties = %d\n" % len(params['addrs']))
        tfile.write(ips)
        tfile.write(ports)
        tfile.close()
        try:
            subprocess.Popen(['java', '-classpath', config['classpath'],
                              '-Djava.library.path=%s' % config['lib_path'],
                              'server.Server', str(params['replica_addrs'][replica][1]),
                              tfile.name, params['sql_addr'], params['db_name']])
        except Exception as e:
            error_exit('Error creating subprocess.\n%s' % e)
        if replica == 0:
            # Wait for first server to finish setting up
            time.sleep(5)

def output_server_addrs():
    '''Output a pkl file that the client can read to contact the servers

    The client conf file is a list of replicas. Each replica is a list of
    addresses corresponding to the server corresponding to that replica.
    '''
    server_addrs = []
    for replica_id in range(config['parallelism']):
        replica = []
        for server in params['addrs']:
            if config['this_addr'] == server:
                replica.append(params['replica_addrs'][replica_id])
            else:
                replica.append(params['other_replica_addrs'][server][replica_id])
        server_addrs.append(replica)
    with open('server-addrs-%d.pkl' % params['id'], 'w') as f:
        pickle.dump(server_addrs, f)

def close_sockets():
    for sock in params['sockets']:
        params['sockets'][sock].shutdown(socket.SHUT_RDWR)
        params['sockets'][sock].close()

if __name__ == "__main__":
    # For debugging only - rewrite config
    base_port = int(sys.argv[1])
    id = int(sys.argv[2])
    config['this_addr'] = ("127.0.0.1", base_port + id)
    config['other_addr'] = []
    for i in range(3):
        if i == id: continue
        config['other_addr'] += [("127.0.0.1", base_port + i)]

    print("Beginning server setup. Establishing setup script connections")
    init_params()
    setup_sockets()
    print("Connection setup successful. Exchanging parameters")
    exchange_params()
    print("Parameter exchange successful. Starting servers")
    start_servers()
    print("Servers started. Generating client config file")
    output_server_addrs()
    print("Config file generated. Closing setup script connections")
    close_sockets()
    print("Setup script connections closed")
