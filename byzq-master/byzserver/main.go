package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/relab/gorums/cmd/byzq-master/byzq"
)

//n.conn, err = grpc.Dial(n.addr, grpc.WithInsecure())

func main() {
	var (
		saddrs = flag.String("addrs", ":8081,:8082,:8083,:8084", "server addresses separated by ','")
		port   = flag.Int("port", 0000, "port to listen on")
		//f           = flag.Int("f", 1, "fault tolerance")
		noauth      = flag.Bool("noauth", true, "don't use authenticated channels")
		key         = flag.String("key", "", "public/private key file this server")
		privKeyFile = flag.String("privkey", "priv-key.pem", "private key file to be used for signatures")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	//Reading key file
	fmt.Println("Reading key file...")
	privKey, err := byzq.ReadKeyfile(*privKeyFile)
	if err != nil {
		dief("error reading keyfile: %v", err)
	}

	// Splitting addresses
	addrs := strings.Split(*saddrs, ",")
	fmt.Println("Other servers ->", addrs)

	// Run only one server.
	fmt.Println("Started serving..")
	go serve(*port, *key, *noauth, addrs, privKey)

	//Connect to all servers // should be goroutine
	fmt.Println("Connecting the servers...")
	conf, mgr, qspec, storageState := connectServers(*port, addrs, privKey)
	fmt.Println("Connected all servers, (conf, mgr, qspec, storageState) ->", conf, mgr, qspec, storageState)

}

func serve(port int, keyFile string, noauth bool, addrs []string, privKey *ecdsa.PrivateKey) {
	fmt.Println("Start Listening on port ->", fmt.Sprintf("localhost:%d", port))
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	defer l.Close()

	if keyFile == "" {
		log.Fatalln("required server keys not provided")
	}

	opts := []grpc.ServerOption{}

	if !noauth {
		creds, err := credentials.NewServerTLSFromFile(keyFile+".crt", keyFile+".key")
		if err != nil {
			log.Fatalf("failed to load credentials: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	} else {
		fmt.Println("Running server without authorization")
	}

	// Creating a gRPC server
	fmt.Println("Creating new grpcServer with opts ->", opts)
	grpcServer := grpc.NewServer(opts...)
	smap := make(map[string]byzq.Value)
	state := &storage{state: smap, serverPort: port, servers: addrs, privKey: privKey}
	byzq.RegisterStorageServer(grpcServer, state)

	// Start serving
	log.Printf("Started serving on port %s ..", l.Addr())
	if err := grpcServer.Serve(l); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}

func connectServers(port int, addrs []string, Key *ecdsa.PrivateKey) (*byzq.Configuration, *byzq.Manager, *byzq.AuthDataQ, *byzq.Content) {
	fmt.Println("in connect servers")
	// Set Dial options
	grpcOpts := []grpc.DialOption{grpc.WithBlock()}
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	dialOpts := byzq.WithGrpcDialOptions(grpcOpts...)

	// Create manager
	mgr, err := byzq.NewManager(addrs, dialOpts, byzq.WithTracing(), byzq.WithDialTimeout(30*time.Second))
	defer mgr.Close()
	if err != nil {
		dief("error creating manager: %v", err)
	}
	fmt.Println("Managed Connections and Created a manager->", mgr)
	ids := mgr.NodeIDs()
	fmt.Println("mgr.NodeIDs() ->", ids)

	// Creating new authorization dataQ
	fmt.Println("Creating NewAuthDataQ...")
	qspec, err := byzq.NewAuthDataQ(len(ids), Key, &Key.PublicKey)
	if err != nil {
		dief("error creating quorum specification: %v", err)
	}

	// Creating Configuration
	fmt.Println("Creating NewConfiguration...")
	conf, err := mgr.NewConfiguration(ids, qspec)
	if err != nil {
		dief("error creating config: %v", err)
	}
	//Create Storage state
	fmt.Println("Creating new storageState...")
	storageState := &byzq.Content{
		Key:       "Hein",
		Value:     "Meling",
		Timestamp: -1,
	}
	fmt.Println("StorageState created ->", storageState)

	return conf, mgr, qspec, storageState
}

type storage struct {
	sync.RWMutex
	state      map[string]byzq.Value
	serverPort int
	servers    []string
	privKey    *ecdsa.PrivateKey
}

func (r *storage) Read(ctx context.Context, k *byzq.Key) (*byzq.Value, error) {
	r.RLock()
	value := r.state[k.Key]
	r.RUnlock()
	return &value, nil
}

func (r *storage) Write(ctx context.Context, v *byzq.Value) (*byzq.WriteResponse, error) {
	//Echowrite should happen here
	fmt.Println("In servers Write")
	wr := &byzq.WriteResponse{Timestamp: v.C.Timestamp}
	r.Lock()
	val, found := r.state[v.C.Key]
	if !found || v.C.Timestamp > val.C.Timestamp {
		r.state[v.C.Key] = *v
	}
	r.Unlock()
	return wr, nil
}

// EchoWrite generates response to a Ping request
func (r *storage) EchoWrite(ctx context.Context, in *byzq.PingMessage) (*byzq.PingMessage, error) {

	if in.Connect {
		fmt.Println("Received message :", in.Greeting, " from :", in.ServerId, "Connect ->", in.Connect)
		fmt.Println("Connecting all servers...")

		// Insecure Dial with grpc
		var secDialOption grpc.DialOption
		secDialOption = grpc.WithInsecure()

		// Create manager
		fmt.Println("Creating new manager with opts...", secDialOption)
		mgr, err := byzq.NewManager(
			r.servers,
			byzq.WithGrpcDialOptions(
				grpc.WithBlock(),
				grpc.WithTimeout(0*time.Millisecond),
				secDialOption,
			),
		)
		defer mgr.Close()
		if err != nil {
			dief("error creating manager: %v", err)
		}
		fmt.Println("Managed Connections and Created a manager->", mgr)
		ids := mgr.NodeIDs()
		fmt.Println("mgr.NodeIDs() ->", ids)

		// Creating new authorization dataQ
		fmt.Println("Creating NewAuthDataQ...")
		qspec, err := byzq.NewAuthDataQ(len(ids)+1, r.privKey, &r.privKey.PublicKey)
		if err != nil {
			dief("error creating quorum specification: %v", err)
		}
		fmt.Println("Created qspec ->", qspec)

		// Creating Configuration
		fmt.Println("Creating NewConfiguration...")
		conf, err := mgr.NewConfiguration(ids, qspec)
		if err != nil {
			dief("error creating config: %v", err)
		}

		fmt.Println("Creating new storageState...")
		storageState := &byzq.Content{
			Key:       "Server to server",
			Value:     "Connection test",
			Timestamp: -1,
		}
		fmt.Println("StorageState created ->", storageState)

		// Writer server.
		fmt.Println("==========Server Writing to other servers...==============")

		storageState.Value = strconv.Itoa(rand.Intn(1 << 8))
		storageState.Timestamp++
		signedState, err := qspec.Sign(storageState)
		if err != nil {
			dief("failed to sign message: %v", err)
		}
		ack, err := conf.Write(context.Background(), signedState)
		fmt.Println("Got acknowlegement that all servers replyed ->", ack)

		if err != nil {
			dief("error writing: %v", err)
		}

		//EchoWrite to other servers
		for _, node := range mgr.Nodes() {
			c := node.StorageClient
			response, err := c.EchoWrite(context.Background(), &byzq.PingMessage{Greeting: "Server to Server write", ServerId: int64(r.serverPort), Connect: false})
			if err != nil {
				log.Fatalf("Error when calling EchoWrite: %s", err)
			}
			fmt.Println("Response from server ", response.ServerId, ":", response.Greeting)

		}

	} else {
		//if connect is false
		fmt.Println("Received :", in.Greeting, " from  :", in.ServerId, "Connect ->", in.Connect)
		return &byzq.PingMessage{Greeting: "Reply to Server to server write ", ServerId: int64(r.serverPort)}, nil
	}
	return &byzq.PingMessage{Greeting: "EchoWrite Completed", ServerId: int64(r.serverPort)}, nil
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func dief(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprint(os.Stderr, "\n")
	flag.Usage()
	os.Exit(2)
}

func removePort(slice []string, port int) []string {
	var answer []string
	s := strconv.Itoa(port)
	stringport := ":" + s
	for i, value := range slice {
		if value == stringport {
			answer = append(slice[:i], slice[i+1:]...)
		}
	}
	return answer
}
