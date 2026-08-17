package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gauthier/passerelle/client"
	"github.com/gauthier/passerelle/client/tui"
	"github.com/gauthier/passerelle/internal/logging"
	"github.com/gauthier/passerelle/internal/origin"
	"github.com/gauthier/passerelle/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	root := &cobra.Command{
		Use:           "passerelle",
		Short:         "Self-hosted HTTP tunnel",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		authCmd(),
		openCmd(),
		closeCmd(),
		listCmd(),
		statusCmd(),
		tuiCmd(),
		daemonCmd(),
		serviceCmd(),
	)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func authCmd() *cobra.Command {
	var insecure bool
	cmd := &cobra.Command{
		Use:     "auth <gateway-url>",
		Aliases: []string{"enroll"},
		Short:   "Connect this device to a gateway",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			token, err := readToken()
			if err != nil {
				return err
			}
			cfg, err := client.Enroll(client.EnrollInput{
				GatewayURL: args[0],
				Token:      token,
				Insecure:   insecure,
			})
			if err != nil {
				return err
			}
			fmt.Printf("authenticated user=%s device=%s gateway=%s\n", cfg.UserID, cfg.ClientID, cfg.EnrollURL)
			return nil
		},
	}
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verify (dev only)")
	return cmd
}

func readToken() (string, error) {
	if t := strings.TrimSpace(os.Getenv("PASSERELLE_TOKEN")); t != "" {
		return t, nil
	}
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "token: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", fmt.Errorf("token required")
		}
		return t, nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", fmt.Errorf("token required (prompt, stdin, or PASSERELLE_TOKEN)")
	}
	t := strings.TrimSpace(line)
	if t == "" {
		return "", fmt.Errorf("token required")
	}
	return t, nil
}

func openCmd() *cobra.Command {
	var subdomain string
	var persist bool
	var https bool
	cmd := &cobra.Command{
		Use:   "open [host:]port",
		Short: "Expose a local HTTP(S) port through the gateway",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ensureDaemon(); err != nil {
				return err
			}
			host, port, err := origin.ParseHostPort(args[0])
			if err != nil {
				return err
			}
			t, err := client.NewAPI("").Open(host, port, subdomain, persist, https)
			if err != nil {
				return err
			}
			fmt.Println(t.PublicURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&subdomain, "subdomain", "", "requested subdomain (optional)")
	cmd.Flags().BoolVar(&persist, "persist", false, "restore this tunnel after reboot")
	cmd.Flags().BoolVar(&https, "https", false, "dial the local origin with TLS (Docker/Apache on 443)")
	return cmd
}

func closeCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "close [id|url|host|port]",
		Short: "Close a tunnel",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ensureDaemon(); err != nil {
				return err
			}
			api := client.NewAPI("")
			list, err := api.List()
			if err != nil {
				return err
			}
			if all {
				if len(list) == 0 {
					fmt.Println("no tunnels")
					return nil
				}
				for _, t := range list {
					if err := api.Close(t.ID); err != nil {
						return err
					}
					fmt.Println(t.PublicURL)
				}
				return nil
			}
			var targets []client.Tunnel
			switch {
			case len(args) == 1:
				targets = client.MatchTunnels(list, args[0])
			case len(list) == 1:
				targets = list
			case len(list) == 0:
				return fmt.Errorf("no tunnels")
			default:
				return fmt.Errorf("several tunnels; pass a URL, hostname, port, or --all")
			}
			if len(targets) == 0 {
				return fmt.Errorf("no tunnel matches %q (try passerelle list)", args[0])
			}
			if len(targets) > 1 {
				return fmt.Errorf("several tunnels match %q; be more specific or use --all", args[0])
			}
			if err := api.Close(targets[0].ID); err != nil {
				return err
			}
			fmt.Println(targets[0].PublicURL)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "close every open tunnel")
	return cmd
}

func listCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List open tunnels",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ensureDaemon(); err != nil {
				return err
			}
			list, err := client.NewAPI("").List()
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(list)
			}
			if len(list) == 0 {
				fmt.Println("no tunnels")
				return nil
			}
			fmt.Printf("%-18s %-42s %-22s %-8s %s\n", "ID", "PUBLIC URL", "LOCAL", "STATUS", "CONNS")
			for _, t := range list {
				fmt.Printf("%-18s %-42s %-22s %-8s %d\n", t.ID, t.PublicURL, t.LocalDisplay(), t.Status, t.Conns)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}

func statusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon and gateway status",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ensureDaemon(); err != nil {
				return err
			}
			st, err := client.NewAPI("").Status()
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			state := "disconnected"
			if st.Connected {
				state = "connected"
			}
			fmt.Printf("Status     %s\nGateway    %s\nTransport  %s\nLatency    %.0f ms\nUser       %s\nDevice     %s\n",
				state, st.Gateway, st.Transport, st.LatencyMS, st.UserID, st.ClientID)
			if st.LastError != "" {
				fmt.Printf("Error      %s\n", st.LastError)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return cmd
}

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal status (does not own tunnels)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ensureDaemon(); err != nil {
				return err
			}
			return tui.Run(client.NewAPI(""))
		},
	}
}

func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the Passerelle daemon in the foreground",
		RunE: func(_ *cobra.Command, _ []string) error {
			d := client.NewDaemon(logging.New("text", "info"), "")
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return d.Run(ctx)
		},
	}
}

func ensureDaemon() error {
	if err := client.WaitForDaemon("", 300*time.Millisecond); err == nil {
		return nil
	}
	fmt.Fprintln(os.Stderr, "daemon is not running; start it with: passerelle daemon")
	fmt.Fprintln(os.Stderr, "or install a user service: passerelle service install")
	return fmt.Errorf("daemon not running")
}
