package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/hellofresh/health-go/v4"
	"github.com/jmoiron/sqlx"
	"github.com/kelseyhightower/envconfig"
	"github.com/mpraski/identity-manager/app/authentication"
	"github.com/mpraski/identity-manager/app/crypto"
	"github.com/mpraski/identity-manager/app/rbac"
	"github.com/mpraski/identity-manager/app/registration"
	"github.com/mpraski/identity-manager/app/secret"
	"github.com/mpraski/identity-manager/app/service"
	"github.com/mpraski/identity-manager/app/storage"
	log "github.com/sirupsen/logrus"
)

type input struct {
	Server struct {
		Address         string        `default:":8080"`
		ReadTimeout     time.Duration `split_words:"true" default:"5s"`
		WriteTimeout    time.Duration `split_words:"true" default:"10s"`
		IdleTimeout     time.Duration `split_words:"true" default:"15s"`
		ShutdownTimeout time.Duration `split_words:"true" default:"30s"`
		RequestTimeout  time.Duration `split_words:"true" default:"45s"`
	}
	Secrets struct {
		SensitiveDataKey string `split_words:"true" required:"true"`
	}
	Database struct {
		DSN string `required:"true"`
	}
	Observability struct {
		Address string `default:":9090"`
	}
}

//go:embed config/rbac/*.yaml
var rbacFs embed.FS

var (
	// Health check
	healthy     int32
	app         = "identity_manager"
	errShutdown = errors.New("shutdown in progress")
)

func init() {
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.WarnLevel)
}

func main() {
	ctx := context.Background()

	log.SetOutput(os.Stdout)

	var i input
	if err := envconfig.Process(app, &i); err != nil {
		log.Fatalf("failed to load input: %v\n", err)
	}

	rules, err := rbac.Make(rbacFs)
	if err != nil {
		log.Fatalf("failed to load RBAC rules: %v\n", err)
	}

	db, err := storage.NewPostgres(ctx, i.Database.DSN)
	if err != nil {
		log.Fatalf("failed to connect to database: %v\n", err)
	}

	defer func() {
		if err = db.Close(); err != nil {
			log.Fatalf("failed to close the database: %v\n", err)
		}
	}()

	gsm, err := secret.NewGoogleSecretManager(ctx)
	if err != nil {
		//nolint:gocritic // whot
		log.Fatalf("failed to connect to google secret manager: %v\n", err)
	}

	defer gsm.Close()

	secretSource := secret.NewBackoffSource(3, 3*time.Second, gsm)

	aesKey, err := secretSource.Get(ctx, i.Secrets.SensitiveDataKey)
	if err != nil {
		log.Fatalf("failed to fetch sensitive data key: %v\n", err)
	}

	aes, err := crypto.NewAES(aesKey)
	if err != nil {
		log.Fatalf("failed to parse sensitive data key: %v\n", err)
	}

	var (
		done                 = make(chan bool)
		quit                 = make(chan os.Signal, 1)
		txManager            = storage.NewTransactionManager(db)
		identityReader       = storage.NewIdentityReader(db)
		identityWriter       = storage.NewIdentityWriter()
		dataReader           = storage.NewDataReader(db, aes)
		dataWriter           = storage.NewDataWriter(aes)
		passwordAuth         = authentication.NewPassword(identityReader)
		passwordRegistration = registration.NewPassword(
			identityReader,
			identityWriter,
			nil,
			nil,
			dataWriter,
			txManager,
			nil,
		)
		authService         = service.NewAuthentication(passwordAuth)
		registrationService = service.NewRegistration(passwordRegistration)
	)

	fmt.Println(rules)
	fmt.Println(dataReader)

	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(i.Server.RequestTimeout))

	r.Mount("/authentication", authService.Router())
	r.Mount("/registration", registrationService.Router())

	main := &http.Server{
		Addr:         i.Server.Address,
		ReadTimeout:  i.Server.ReadTimeout,
		WriteTimeout: i.Server.WriteTimeout,
		IdleTimeout:  i.Server.IdleTimeout,
		Handler:      r,
	}

	observability, err := newObservabilityServer(&i, db)
	if err != nil {
		log.Fatalf("failed to setup obvervability: %v\n", err)
	}

	go func() {
		log.Println("starting observability server at", i.Observability.Address)

		if errs := observability.ListenAndServe(); errs != nil && errs != http.ErrServerClosed {
			log.Fatalf("failed to start observability server on %s: %v\n", i.Observability.Address, errs)
		}
	}()

	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		log.Println("server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, i.Server.ShutdownTimeout)
		defer cancel()

		main.SetKeepAlivesEnabled(false)
		observability.SetKeepAlivesEnabled(false)

		if err := main.Shutdown(ctx); err != nil {
			log.Fatalf("failed to gracefully shutdown the server: %v\n", err)
		}

		if err := observability.Shutdown(ctx); err != nil {
			log.Fatalf("failed to gracefully shutdown observability server: %v\n", err)
		}

		close(done)
	}()

	log.Println("server is ready to handle requests at", i.Server.Address)
	atomic.StoreInt32(&healthy, 1)

	if err := main.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to listen on %s: %v\n", i.Server.Address, err)
	}

	<-done
	log.Println("server stopped")
}

func healthz(db *sqlx.DB) (http.Handler, error) {
	h, err := health.New(health.WithChecks(health.Config{
		Name:    "database",
		Timeout: time.Second * 5,
		Check: func(ctx context.Context) error {
			if err := db.PingContext(ctx); err != nil {
				return err
			}

			if _, err := db.ExecContext(ctx, `SELECT VERSION()`); err != nil {
				return err
			}

			return nil
		}},
		health.Config{
			Name:    "shutdown",
			Timeout: time.Second,
			Check: func(ctx context.Context) error {
				if atomic.LoadInt32(&healthy) == 0 {
					return errShutdown
				}

				return nil
			},
		},
	))

	if err != nil {
		return nil, fmt.Errorf("failed to set up health checks: %w", err)
	}

	return h.Handler(), nil
}

func newObservabilityServer(cfg *input, db *sqlx.DB) (*http.Server, error) {
	h, err := healthz(db)
	if err != nil {
		return nil, fmt.Errorf("failed to setup healthz: %w", err)
	}

	router := http.NewServeMux()
	router.Handle("/healthz", h)

	return &http.Server{
		Addr:         cfg.Observability.Address,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		Handler:      router,
	}, nil
}
