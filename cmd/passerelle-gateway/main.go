package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gauthier/passerelle/gateway"
	"github.com/gauthier/passerelle/gateway/identity"
	"github.com/gauthier/passerelle/internal/logging"
	"github.com/gauthier/passerelle/internal/version"
	"github.com/spf13/cobra"
)

func main() {
	var dataDir, configPath string
	root := &cobra.Command{
		Use:           "passerelle-gateway",
		Short:         "Passerelle public gateway",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory (CA, users, tokens)")
	root.PersistentFlags().StringVar(&configPath, "config", "", "TOML config file")

	root.AddCommand(runCmd(&dataDir, &configPath))
	root.AddCommand(userCmd(&dataDir))
	root.AddCommand(tokenCmd(&dataDir))
	root.AddCommand(deviceCmd(&dataDir))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func resolveDir(dataDir *string) string {
	if dataDir != nil && *dataDir != "" {
		return *dataDir
	}
	if d := os.Getenv("PASSERELLE_DATA_DIR"); d != "" {
		return d
	}
	return "/var/lib/passerelle"
}

func runCmd(dataDir, configPath *string) *cobra.Command {
	var dev bool
	var baseDomain, listenHTTPS, listenHTTP, listenQUIC, tlsCert, tlsKey, logFormat string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the gateway",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := gateway.Defaults()
			if *configPath != "" {
				loaded, err := gateway.LoadConfig(*configPath)
				if err != nil {
					return err
				}
				cfg = loaded
			}
			if *dataDir != "" {
				cfg.DataDir = *dataDir
			}
			if dev {
				cfg.Dev = true
				cfg.LogFormat = "text"
				if cfg.DataDir == "/var/lib/passerelle" {
					cfg.DataDir = "./data"
				}
				cfg.ListenHTTPS = "127.0.0.1:8443"
				cfg.ListenHTTP = "127.0.0.1:8080"
				cfg.ListenQUIC = "127.0.0.1:8443"
				cfg.PublicScheme = "https"
				cfg.Metrics.Listen = "127.0.0.1:9091"
			}
			if baseDomain != "" {
				cfg.BaseDomain = baseDomain
			}
			if listenHTTPS != "" {
				cfg.ListenHTTPS = listenHTTPS
			}
			if listenHTTP != "" {
				cfg.ListenHTTP = listenHTTP
			}
			if listenQUIC != "" {
				cfg.ListenQUIC = listenQUIC
			}
			if tlsCert != "" {
				cfg.TLSCert = tlsCert
			}
			if tlsKey != "" {
				cfg.TLSKey = tlsKey
			}
			if logFormat != "" {
				cfg.LogFormat = logFormat
			}
			log := logging.New(cfg.LogFormat, cfg.LogLevel)
			srv, err := gateway.New(cfg, log)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return srv.Run(ctx)
		},
	}
	cmd.Flags().BoolVar(&dev, "dev", false, "development defaults (loopback ports, self-signed TLS)")
	cmd.Flags().StringVar(&baseDomain, "base-domain", "", "base DNS name for tunnel hostnames")
	cmd.Flags().StringVar(&listenHTTPS, "listen-https", "", "TCP HTTPS/tunnel listen address")
	cmd.Flags().StringVar(&listenHTTP, "listen-http", "", "TCP HTTP listen address")
	cmd.Flags().StringVar(&listenQUIC, "listen-quic", "", "UDP QUIC listen address")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "public TLS certificate file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "public TLS key file")
	cmd.Flags().StringVar(&logFormat, "log-format", "", "text or json")
	return cmd
}

func userCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{Use: "user", Short: "Manage users"}
	add := &cobra.Command{
		Use:   "add <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Create a user",
		RunE: func(_ *cobra.Command, args []string) error {
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			u, err := st.AddUser(args[0], identity.DefaultQuotas())
			if err != nil {
				return err
			}
			fmt.Printf("user %s created (max_devices=%d max_tunnels=%d max_conns=%d)\n", u.Name, u.Quotas.MaxDevices, u.Quotas.MaxTunnels, u.Quotas.MaxConns)
			return nil
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(_ *cobra.Command, _ []string) error {
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			users, err := st.ListUsers()
			if err != nil {
				return err
			}
			for _, u := range users {
				fmt.Printf("%s revoked=%v devices_quota=%d\n", u.Name, u.Revoked, u.Quotas.MaxDevices)
			}
			return nil
		},
	}
	rev := &cobra.Command{
		Use:   "revoke <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Revoke a user and their devices",
		RunE: func(_ *cobra.Command, args []string) error {
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			return st.RevokeUser(args[0])
		},
	}
	cmd.AddCommand(add, list, rev)
	return cmd
}

func tokenCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage enrollment tokens"}
	var user string
	var ttl time.Duration
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a one-time enrollment token",
		RunE: func(_ *cobra.Command, _ []string) error {
			if user == "" {
				return fmt.Errorf("--user is required")
			}
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			tok, err := st.CreateToken(user, ttl)
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		},
	}
	create.Flags().StringVar(&user, "user", "", "user name")
	create.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime")
	cmd.AddCommand(create)
	return cmd
}

func deviceCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{Use: "device", Short: "Manage enrolled devices"}
	var user string
	list := &cobra.Command{
		Use:   "list",
		Short: "List devices",
		RunE: func(_ *cobra.Command, _ []string) error {
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			devs, err := st.ListDevices(user)
			if err != nil {
				return err
			}
			for _, d := range devs {
				fmt.Printf("%s user=%s revoked=%v serial=%s\n", d.ClientID, d.UserID, d.Revoked, d.Serial)
			}
			return nil
		},
	}
	list.Flags().StringVar(&user, "user", "", "filter by user")
	rev := &cobra.Command{
		Use:   "revoke <client-id>",
		Args:  cobra.ExactArgs(1),
		Short: "Revoke a device certificate",
		RunE: func(_ *cobra.Command, args []string) error {
			st, err := identity.Open(resolveDir(dataDir))
			if err != nil {
				return err
			}
			return st.RevokeDevice(args[0])
		},
	}
	cmd.AddCommand(list, rev)
	return cmd
}
