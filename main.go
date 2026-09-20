package main

import (
	"context"
	"flag"
	"github.com/wmsing/agent-firewall/eval"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func startMockBackend(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "ok %s %s\n", r.Method, r.URL.Path)
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("mock backend: %v", err)
		}
	}()
	return srv
}

func main() {
	listen := flag.String("listen", ":8286", "firewall listen address")
	targetStr := flag.String("target", "http://127.0.0.1:8287", "upstream API URL")
	withBackend := flag.Bool("backend", true, "start mock backend on :8287")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	var backendSrv *http.Server
	if *withBackend {
		backendSrv = startMockBackend(":8287")
		log.Println("mock backend listening on :8287")
	}

	target, err := url.Parse(*targetStr)
	if err != nil {
		log.Fatalf("invalid -target: %v", err)
	}

	handler := NewFirewallHandler(target, eval.NewRiskEvaluator())
	srv := &http.Server{Addr: *listen, Handler: handler}

	go func() {
		log.Printf("firewall listening on %s -> %s", *listen, target)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("firewall: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if backendSrv != nil {
		_ = backendSrv.Shutdown(ctx)
	}
}
