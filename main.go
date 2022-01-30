package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/mpraski/identity-manager/app/rbac"
)

type input struct {
	Server struct {
		Address         string        `default:":8080"`
		ReadTimeout     time.Duration `split_words:"true" default:"5s"`
		WriteTimeout    time.Duration `split_words:"true" default:"10s"`
		IdleTimeout     time.Duration `split_words:"true" default:"15s"`
		ShutdownTimeout time.Duration `split_words:"true" default:"30s"`
	}
	Observability struct {
		Address string `default:":9090"`
	}
}

//go:embed config/rbac/*.yaml
var rbacFs embed.FS

var (
	// Health check
	healthy int32
	app     = "identity_manager"
)

func main() {
	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	logger.Println("server is starting...")

	var i input
	if err := envconfig.Process(app, &i); err != nil {
		logger.Fatalf("failed to load input: %v\n", err)
	}

	cfg, err := rbac.Make(rbacFs)
	if err != nil {
		panic(err)
	}

	j, err := json.Marshal(cfg.ScopesForGroup("admins"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(j))

	var (
		done = make(chan bool)
		quit = make(chan os.Signal, 1)
	)

	observability := newObservabilityServer(&i)

	go func() {
		logger.Println("starting observability server at", i.Observability.Address)

		if errs := observability.ListenAndServe(); errs != nil && errs != http.ErrServerClosed {
			logger.Fatalf("failed to start observability server on %s: %v\n", i.Observability.Address, errs)
		}
	}()

	main := &http.Server{
		Addr:         i.Server.Address,
		ReadTimeout:  i.Server.ReadTimeout,
		WriteTimeout: i.Server.WriteTimeout,
		IdleTimeout:  i.Server.IdleTimeout,
	}

	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		logger.Println("server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), i.Server.ShutdownTimeout)
		defer cancel()

		main.SetKeepAlivesEnabled(false)
		observability.SetKeepAlivesEnabled(false)

		if err := main.Shutdown(ctx); err != nil {
			logger.Fatalf("failed to gracefully shutdown the server: %v\n", err)
		}

		if err := observability.Shutdown(ctx); err != nil {
			logger.Fatalf("failed to gracefully shutdown observability server: %v\n", err)
		}

		close(done)
	}()

	logger.Println("server is ready to handle requests at", i.Server.Address)
	atomic.StoreInt32(&healthy, 1)

	if err := main.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("failed to listen on %s: %v\n", i.Server.Address, err)
	}

	<-done
	logger.Println("server stopped")
}

func healthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func newObservabilityServer(cfg *input) *http.Server {
	router := http.NewServeMux()
	router.Handle("/healthz", healthz())

	return &http.Server{
		Addr:         cfg.Observability.Address,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		Handler:      router,
	}
}
