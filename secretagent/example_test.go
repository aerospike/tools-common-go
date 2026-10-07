package secretagent_test

import (
	"context"
	"log"

	"github.com/aerospike/tools-common-go/secretagent"
)

func ExampleClient_Resolve() {
	tlsConfig, err := secretagent.NewTLSConfig(secretagent.TLSOptions{
		CAFile: "/etc/aerospike/secret-agent-ca.pem",
	})
	if err != nil {
		log.Fatal(err)
	}

	client, err := secretagent.NewClient(secretagent.Config{
		Address: "127.0.0.1:3005",
		TLS:     tlsConfig,
		Base64:  true,
	})
	if err != nil {
		log.Fatal(err)
	}

	password, err := client.Resolve(context.Background(), "secrets:aerospike:password")
	if err != nil {
		log.Fatal(err)
	}

	_ = password
}
