package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

const addr = "localhost:4242"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.

type cmd_t struct {
	Help   bool
	Server bool
}

var cmd cmd_t

func init() {
	flag.BoolVar(&cmd.Help, "h", false, "thsi help")
	flag.BoolVar(&cmd.Server, "s", false, "echo server.")
}

func main() {

	flag.Parse()

	if cmd.Help {
		flag.Usage()
		return
	}

	if cmd.Server {
		log.Println("quic echo server start ....")
		log.Fatal(echo_server())
		log.Println("quic echo server stop.")
	} else {
		log.Println("quic echo client start ....")
		err := client_main()
		if err != nil {
			panic(err)
		}
		log.Println("quic echo client stop.")
	}

}

// Start a server that echos all data on the first stream opened by the client
func echo_server() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		go func() {
			for {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					log.Println(err)
					stream.Close()
				}
				go func() {
					// Echo through the loggingWriter
					_, err = io.Copy(loggingWriter{stream}, stream)
					if err != nil {
						log.Println(err)
					}
				}()
			}
		}()
	}

	return nil
}

func client_main() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	//quic_Conf := &quic.Config{}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	for {
		cur_time := time.Now()
		fmt.Printf("Client: Sending '%s'\n", cur_time.String())
		_, err = stream.Write([]byte(cur_time.String()))
		if err != nil {
			return err
		}
		buf := make([]byte, len(cur_time.String()))
		_, err = io.ReadFull(stream, buf)
		if err != nil {
			return err
		}
		fmt.Printf("Client: Got '%s'\n", buf)

		time.Sleep(2 * time.Second)
	}

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
