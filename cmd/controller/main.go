package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	core "github.com/yanmarques/jails-controller/pkg/core"
)

func main() {
	configPath := flag.String("config", core.DEFAULT_CONFIG_PATH, "Path to configuration")

	flag.Parse()

	log.Printf("config path: %s\n", *configPath)

	reconciler := core.NewReconcilerOrFail(*configPath)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		cancel()
	}()

	reconciler.Reconcile()

	for {
		timer := time.After(time.Duration(reconciler.Config.PollInterval) * time.Second)
		select {
		case <-ctx.Done():
			return
		case <-timer:
			reconciler.Reconcile()
		}

	}
}
