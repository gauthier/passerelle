package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"text/template"

	"github.com/gauthier/passerelle/client"
	"github.com/spf13/cobra"
)

func serviceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "service", Short: "Install or control the user-level daemon"}
	cmd.AddCommand(
		&cobra.Command{Use: "install", Short: "Install user service (launchd / systemd --user / logon task)", RunE: func(*cobra.Command, []string) error { return serviceInstall() }},
		&cobra.Command{Use: "uninstall", Short: "Remove user service", RunE: func(*cobra.Command, []string) error { return serviceUninstall() }},
		&cobra.Command{Use: "start", Short: "Start user service", RunE: func(*cobra.Command, []string) error { return serviceCtl("start") }},
		&cobra.Command{Use: "stop", Short: "Stop user service", RunE: func(*cobra.Command, []string) error { return serviceCtl("stop") }},
	)
	return cmd
}

func exe() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func serviceInstall() error {
	bin, err := exe()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, "Library", "LaunchAgents")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		plist := filepath.Join(dir, "com.passerelle.daemon.plist")
		tmpl := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.passerelle.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{{.Bin}}</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{{.Log}}</string>
  <key>StandardErrorPath</key><string>{{.Log}}</string>
</dict>
</plist>
`
		logp := filepath.Join(client.Dir(), "daemon.log")
		if err := os.MkdirAll(client.Dir(), 0o700); err != nil {
			return err
		}
		f, err := os.Create(plist)
		if err != nil {
			return err
		}
		defer f.Close()
		t := template.Must(template.New("p").Parse(tmpl))
		if err := t.Execute(f, map[string]string{"Bin": bin, "Log": logp}); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "unload", plist).Run()
		return exec.Command("launchctl", "load", plist).Run()
	case "linux":
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".config", "systemd", "user")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		unit := filepath.Join(dir, "passerelle.service")
		content := fmt.Sprintf(`[Unit]
Description=Passerelle tunnel daemon
After=network-online.target

[Service]
ExecStart=%s daemon
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, bin)
		if err := os.WriteFile(unit, []byte(content), 0o644); err != nil {
			return err
		}
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		_ = exec.Command("systemctl", "--user", "enable", "--now", "passerelle.service").Run()
		return nil
	default:
		return fmt.Errorf("service install on %s is not automated; run `passerelle daemon` at logon", runtime.GOOS)
	}
}

func serviceUninstall() error {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.passerelle.daemon.plist")
		_ = exec.Command("launchctl", "unload", plist).Run()
		return os.Remove(plist)
	case "linux":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "passerelle.service").Run()
		home, _ := os.UserHomeDir()
		return os.Remove(filepath.Join(home, ".config", "systemd", "user", "passerelle.service"))
	default:
		return nil
	}
}

func serviceCtl(action string) error {
	switch runtime.GOOS {
	case "darwin":
		if action == "start" {
			return exec.Command("launchctl", "start", "com.passerelle.daemon").Run()
		}
		return exec.Command("launchctl", "stop", "com.passerelle.daemon").Run()
	case "linux":
		return exec.Command("systemctl", "--user", action, "passerelle.service").Run()
	default:
		return fmt.Errorf("unsupported")
	}
}
