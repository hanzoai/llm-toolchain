// Command probe exercises a LIVE llm-toolchain service over ZAP — the
// out-of-process smoke test. It mints a synthetic CapKindIAMSession capability
// (PermAll), connects to the service at --addr, drives one method per category
// (a schema create→getAll, a model config set→get), and a pipelined
// create-then-list, printing each result. Exit 0 on success, non-zero on any
// failure.
//
//	go run ./cmd/probe --addr 127.0.0.1:9994 --peer llm-toolchain
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	zaplib "github.com/luxfi/zap"

	gen "github.com/hanzoai/llm-toolchain/gen"
	"github.com/hanzoai/llm-toolchain/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9994", "service ZAP address")
	peer := flag.String("peer", "llm-toolchain", "service ZAP node id")
	flag.Parse()

	if err := run(*addr, *peer); err != nil {
		fmt.Fprintln(os.Stderr, "PROBE FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("PROBE OK")
}

func run(addr, peer string) error {
	capBuf, err := server.SyntheticCap(server.PermAll)
	if err != nil {
		return fmt.Errorf("mint cap: %w", err)
	}

	// create + pipelined-getAll need two connections (FIFO transport). Each gets
	// a UNIQUE node id — the server rejects duplicate peer ids (EOF on
	// handshake), so id collisions silently drop the second connection.
	clientN := 0
	mkClient := func(log *[]server.SendEvent) (*server.Client, func(), error) {
		clientN++
		node := zaplib.NewNode(zaplib.NodeConfig{
			NodeID:      fmt.Sprintf("llmtc-probe-%d-%d", os.Getpid(), clientN),
			Port:        0, // OS-assigned ephemeral port
			NoDiscovery: true,
		})
		if err := node.Start(); err != nil {
			return nil, nil, err
		}
		c, err := server.Dial(node, addr, peer, capBuf)
		if err != nil {
			node.Stop()
			return nil, nil, err
		}
		if log != nil {
			c.WithSendLog(log)
		}
		return c, node.Stop, nil
	}

	var log []server.SendEvent
	cli, stop1, err := mkClient(&log)
	if err != nil {
		return err
	}
	defer stop1()
	dep, stop2, err := mkClient(&log)
	if err != nil {
		return err
	}
	defer stop2()

	time.Sleep(200 * time.Millisecond) // handshake settle

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const project = "probe-project"

	// 1. schemaCreate + schemaGetAll
	ref, err := cli.SchemaCreate(ctx, gen.NamedDocParamsInput{
		ProjectId: project, Name: "probe-schema", Description: "smoke", Body: `{"type":"object"}`,
	})
	if err != nil {
		return fmt.Errorf("SchemaCreate: %w", err)
	}
	fmt.Printf("SchemaCreate: id=%s name=%s\n", ref.Id(), ref.Name())

	list, err := cli.SchemaGetAll(ctx, project)
	if err != nil {
		return fmt.Errorf("SchemaGetAll: %w", err)
	}
	fmt.Printf("SchemaGetAll: %d documents\n", list.Data().Len())

	// 2. modelSetConfig + modelGetConfig
	cfg, err := cli.ModelSetConfig(ctx, gen.ModelConfigParamsInput{
		ProjectId: project, DefaultModel: "zen4", Temperature: 0.5, MaxTokens: 2048,
	})
	if err != nil {
		return fmt.Errorf("ModelSetConfig: %w", err)
	}
	fmt.Printf("ModelSetConfig: defaultModel=%s temp=%.2f maxTokens=%d\n",
		cfg.DefaultModel(), cfg.Temperature(), cfg.MaxTokens())

	got, err := cli.ModelGetConfig(ctx, project)
	if err != nil {
		return fmt.Errorf("ModelGetConfig: %w", err)
	}
	fmt.Printf("ModelGetConfig: defaultModel=%s maxTokens=%d\n", got.DefaultModel(), got.MaxTokens())

	// 3. Pipelined schemaCreate + schemaGetAll (create-then-use).
	log = log[:0]
	pref, plist, err := cli.PipelineCreateThenList(ctx, dep, gen.NamedDocParamsInput{
		ProjectId: project, Name: "probe-pipelined", Description: "pipeline", Body: `{"type":"string"}`,
	})
	if err != nil {
		return fmt.Errorf("PipelineCreateThenList: %w", err)
	}
	fmt.Printf("Pipeline: created id=%s, getAll saw %d documents\n", pref.Id(), plist.Data().Len())
	fmt.Printf("Pipeline send log: %s\n", fmtLog(log))

	// Verify the pipelining invariant: ≥2 sends before the first recv.
	sends, firstRecv := 0, -1
	for i, e := range log {
		if e.Kind == "recv" {
			firstRecv = i
			break
		}
		sends++
	}
	if firstRecv == -1 || sends < 2 {
		return fmt.Errorf("pipelining not observed: %d sends before first recv", sends)
	}
	fmt.Printf("Pipelining verified: %d calls in flight before the first answer\n", sends)
	return nil
}

func fmtLog(log []server.SendEvent) string {
	out := ""
	for _, e := range log {
		m := "create"
		if e.Method == server.MethodSchemaGetAll {
			m = "getAll"
		}
		out += fmt.Sprintf("%s(%s,p=%d,t=%d) ", e.Kind, m, e.PromiseID, e.Target)
	}
	return out
}
