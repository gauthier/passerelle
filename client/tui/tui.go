package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gauthier/passerelle/client"
)

type snapshot struct {
	Status  client.Status   `json:"status"`
	Tunnels []client.Tunnel `json:"tunnels"`
}

type model struct {
	api    *client.APIClient
	snap   snapshot
	table  table.Model
	err    error
	width  int
	height int
}

func Run(api *client.APIClient) error {
	m := model{api: api, table: newTable()}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func newTable() table.Model {
	cols := []table.Column{
		{Title: "ID", Width: 16},
		{Title: "PUBLIC URL", Width: 36},
		{Title: "LOCAL", Width: 22},
		{Title: "STATUS", Width: 10},
		{Title: "CONNECTIONS", Width: 12},
	}
	t := table.New(table.WithColumns(cols), table.WithHeight(8))
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).Foreground(lipgloss.Color("252"))
	s.Selected = s.Selected.Foreground(lipgloss.Color("15")).Bold(false)
	t.SetStyles(s)
	return t
}

type tickMsg struct{}
type snapMsg snapshot
type errMsg struct{ error }

func (m model) Init() tea.Cmd { return tea.Batch(m.refresh(), tick()) }

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m model) refresh() tea.Cmd {
	api := m.api
	return func() tea.Msg {
		st, err := api.Status()
		if err != nil {
			return errMsg{err}
		}
		list, err := api.List()
		if err != nil {
			return errMsg{err}
		}
		return snapMsg{Status: *st, Tunnels: list}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		return m, tea.Batch(m.refresh(), tick())
	case snapMsg:
		m.snap = snapshot(msg)
		m.err = nil
		rows := make([]table.Row, 0, len(m.snap.Tunnels))
		for _, t := range m.snap.Tunnels {
			rows = append(rows, table.Row{t.ID, t.PublicURL, t.LocalDisplay(), t.Status, fmt.Sprintf("%d", t.Conns)})
		}
		m.table.SetRows(rows)
	case errMsg:
		m.err = msg
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() string {
	title := lipgloss.NewStyle().Bold(true).Render("Passerelle")
	st := m.snap.Status
	conn := "Disconnected"
	if st.Connected {
		conn = "Connected"
	}
	body := fmt.Sprintf("Gateway      %s\nStatus       %s\nTransport    %s\nLatency      %.0f ms\n",
		empty(st.Gateway, "-"), conn, empty(st.Transport, "-"), st.LatencyMS)
	if st.LastError != "" {
		body += "Error        " + st.LastError + "\n"
	}
	body += "\nTunnels\n" + m.table.View() + "\n"
	body += fmt.Sprintf("\nTraffic\n↓ %s\n↑ %s\n", human(st.BytesIn), human(st.BytesOut))
	body += "\nq quit  —  closing this view does not close tunnels"
	if m.err != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.err.Error())
	}
	return title + "\n\n" + body
}

func empty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func human(n int64) string {
	const k = 1024.0
	f := float64(n)
	switch {
	case f >= k*k*k:
		return fmt.Sprintf("%.1f GB", f/(k*k*k))
	case f >= k*k:
		return fmt.Sprintf("%.1f MB", f/(k*k))
	case f >= k:
		return fmt.Sprintf("%.1f KB", f/k)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
