package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/relab/gorums/cmd/byzq-master"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	var (
		port   = flag.Int("port", 0000, "port to listen on")
		f      = flag.Int("f", 0, "fault tolerance")
		noauth = flag.Bool("noauth", true, "don't use authenticated channels")
		key    = flag.String("key", "", "public/private key file this server")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	fmt.Println("port ->", *port)
	fmt.Println("f ->", *f)
	fmt.Println("noauth ->", *noauth)
	fmt.Println("key ->", *key)

	fmt.Println("CORRECT FILE")

	if *f > 0 {
		// We are running only local since we have asked for 3f+1 servers.
		done := make(chan bool)
		n := 3**f + 1
		for i := 0; i < n; i++ {
			go serve(*port+i, *key, *noauth)
		}
		// Wait indefinitely.
		<-done
	}

	// Run only one server.
	fmt.Println("Runing server on port- > ", *port)
	serve(*port, *key, *noauth)
}

func serve(port int, keyFile string, noauth bool) {
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

	// Creating the server
	// Server represents the gRPC server
	fmt.Println("Creating new grpcServer with opts ->", opts)
	grpcServer := grpc.NewServer(opts...)
	smap := make(map[string]byzq.Value)
	byzq.RegisterStorageServer(grpcServer, &storage{state: smap})
	log.Printf("server %s running...", l.Addr())

	// start the server
	if err := grpcServer.Serve(l); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}

}

type storage struct {
	sync.RWMutex
	state map[string]byzq.Value
}

func (r *storage) Read(ctx context.Context, k *byzq.Key) (*byzq.Value, error) {
	r.RLock()
	value := r.state[k.Key]
	r.RUnlock()
	return &value, nil
}

func (r *storage) Write(ctx context.Context, v *byzq.Value) (*byzq.WriteResponse, error) {
	wr := &byzq.WriteResponse{Timestamp: v.C.Timestamp}
	r.Lock()
	val, found := r.state[v.C.Key]
	if !found || v.C.Timestamp > val.C.Timestamp {
		r.state[v.C.Key] = *v
	}
	r.Unlock()
	return wr, nil
}

// SayHello generates response to a Ping request
func (r *storage) SayHello(ctx context.Context, in *byzq.PingMessage) (*byzq.PingMessage, error) {
	log.Printf("Received message : %s", in.Greeting)
	return &byzq.PingMessage{Greeting: "Hallo from the server"}, nil
}
