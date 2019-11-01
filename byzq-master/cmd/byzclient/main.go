package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/relab/gorums/cmd/byzq-master"
	"github.com/relab/gorums/cmd/demo/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	var (
		port     = flag.Int("port", 8080, "port where local server is listening")
		saddrs   = flag.String("addrs", ":8081,:8082,:8083,:8084", "server addresses separated by ','")
		f        = flag.Int("f", 1, "fault tolerance, supported values f=1,2,3 (this is ignored if addrs is provided)")
		noauth   = flag.Bool("noauth", true, "don't use authenticated channels")
		generate = flag.Bool("generate", false, "generate public/private key-pair and save to file provided by -key")
		writer   = flag.Bool("writer", false, "set this client to be writer only (default is reader only)")
		keyFile  = flag.String("key", "priv-key.pem", "private key file to be used for signatures")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *generate {
		// Generate key file and exit.
		err := byzq.GenerateKeyfile(*keyFile)
		if err != nil {
			dief("error generating public/private key-pair: %v", err)
		}
		os.Exit(0)
	}
	if *saddrs == "" {
		fmt.Println("inside")
		// Use local addresses only..
		if *f > 3 || *f < 1 {
			dief("only f=1,2,3 is allowed")
		}
		n := 3**f + 1
		var buf bytes.Buffer
		for i := 0; i < n; i++ {
			buf.WriteString(":")
			buf.WriteString(strconv.Itoa(*port + i))
			buf.WriteString(",")
		}
		b := buf.String()
		*saddrs = b[:len(b)-1]
	}
	fmt.Println("CORRECT CLIENT")
	addrs := strings.Split(*saddrs, ",")
	fmt.Println("Default servers ->", addrs)

	if len(addrs) == 0 {
		dief("no server addresses provided")
	}
	log.Printf("#addrs: %d (%v)", len(addrs), *saddrs)

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// Secure Dial with grpc
	var secDialOption grpc.DialOption
	if *noauth {
		fmt.Println("Insecure Dial options")
		secDialOption = grpc.WithInsecure()
	} else {
		fmt.Println("Authorization...")
		clientCreds, err := credentials.NewClientTLSFromFile("cert/server.crt", "127.0.0.1")
		if err != nil {
			dief("error creating credentials: %v", err)
		}
		secDialOption = grpc.WithTransportCredentials(clientCreds)
		fmt.Println("Authorization succesefull")
	}

	fmt.Println("Reading key file...")
	key, err := byzq.ReadKeyfile(*keyFile)
	if err != nil {
		dief("error reading keyfile: %v", err)
	}

	fmt.Println("Creating new manager with opts...", secDialOption)
	mgr, err := byzq.NewManager(
		addrs,
		byzq.WithGrpcDialOptions(
			grpc.WithBlock(),
			grpc.WithTimeout(0*time.Millisecond),
			secDialOption,
		),
	)

	fmt.Println("Managed Connections and Created a manager->", mgr)

	if err != nil {
		dief("error creating manager: %v", err)
	}
	defer mgr.Close()

	ids := mgr.NodeIDs()
	fmt.Println("mgr.NodeIDs() ->", ids)

	fmt.Println("Creating NewAuthDataQ...")
	qspec, err := byzq.NewAuthDataQ(len(ids), key, &key.PublicKey)
	if err != nil {
		dief("error creating quorum specification: %v", err)
	}

	fmt.Println("Creating NewConfiguration...")
	conf, err := mgr.NewConfiguration(ids, qspec)
	if err != nil {
		dief("error creating config: %v", err)
	}

	fmt.Println("Creating new storageState...")
	storageState := &byzq.Content{
		Key:       "Hein",
		Value:     "Meling",
		Timestamp: -1,
	}
	fmt.Println("StorageState created ->", storageState)

	for {
		if *writer {
			// Writer client.
			fmt.Println("==========Client Writing to servers...==============")

			storageState.Value = strconv.Itoa(rand.Intn(1 << 8))
			fmt.Println("Chosing a random value ->", storageState.Value)

			storageState.Timestamp++
			fmt.Println("Increased timestamp ->", storageState.Timestamp)

			signedState, err := qspec.Sign(storageState)
			fmt.Println("Signed a storage state ->", signedState)

			if err != nil {
				dief("failed to sign message: %v", err)
			}

			fmt.Println("Writing the state to the servers...")
			ack, err := conf.Write(context.Background(), signedState)
			fmt.Println("Got acknowlegement that all servers replyed ->", ack)

			if err != nil {
				dief("error writing: %v", err)
			}

			///////////////////////////////////////////////////////////////////////////////////////////////////

			response, err := conf.SayHello(context.Background(), &api.PingMessage{Greeting: "Hello from the client"})
			if err != nil {
				log.Fatalf("Error when calling SayHello: %s", err)
			}
			log.Printf("Response from server: %s", response.Greeting)

			///////////////////////////////////////////////////////////////////////////////////////////////////
			time.Sleep(15 * time.Second)
		} else {
			// Reader client.
			val, err := conf.Read(context.Background(), &byzq.Key{Key: storageState.Key})
			if err != nil {
				dief("error reading: %v", err)
			}
			fmt.Println("ReadReturn: " + val.String())
			time.Sleep(10000 * time.Millisecond)
		}
	}
}

func dief(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprint(os.Stderr, "\n")
	flag.Usage()
	os.Exit(2)
}
