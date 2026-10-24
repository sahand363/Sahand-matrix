package hub

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"sahand-matrix/pkg/models"
)

type NodeManager struct {
	mu        sync.RWMutex
	nodes     map[string]*models.ServerNode
	passwords map[string]string
}

func NewNodeManager(localIP string) *NodeManager {
	nm := &NodeManager{
		nodes:     make(map[string]*models.ServerNode),
		passwords: make(map[string]string),
	}
	nm.nodes["local-s1"] = &models.ServerNode{
		ID:          "local-s1",
		Name:        "Primary Server (Local Hub)",
		Role:        "iran",
		Host:        localIP,
		SSHPort:     22,
		SSHUser:     "root",
		AgentPort:   9444,
		Connected:   true,
		DeployState: "READY",
		DeployPct:   100,
		DeployLogs:  []string{"[100%] Local sniffer ready on Primary Hub."},
		UpdatedAt:   time.Now().UTC(),
	}
	return nm
}

// ListNodes returns servers in a stable, deterministic sorted order so the UI never flickers.
func (nm *NodeManager) ListNodes() []*models.ServerNode {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var list []*models.ServerNode
	for _, n := range nm.nodes {
		cp := *n
		list = append(list, &cp)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ID == "local-s1" {
			return true
		}
		if list[j].ID == "local-s1" {
			return false
		}
		return list[i].ID < list[j].ID
	})
	return list
}

func (nm *NodeManager) GetNode(id string) (*models.ServerNode, bool) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	n, ok := nm.nodes[id]
	if !ok {
		return nil, false
	}
	cp := *n
	return &cp, true
}

// DeleteNode removes a server from the list (except the primary local-s1 hub).
func (nm *NodeManager) DeleteNode(id string) bool {
	if id == "local-s1" {
		return false
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()
	delete(nm.nodes, id)
	delete(nm.passwords, id)
	return true
}

// MarkNodeOnline locks a node at 100% READY when its agent responds to live snapshots.
func (nm *NodeManager) MarkNodeOnline(id string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if n, ok := nm.nodes[id]; ok && n.DeployState != "DEPLOYING" && n.DeployPct < 100 {
		n.DeployPct = 100
		n.DeployState = "READY"
		n.Connected = true
		n.DeployLogs = append(n.DeployLogs, "[100%] Live sahand-agent telemetry verified on port 9444!")
	}
}

func (nm *NodeManager) AddAndVerifySSH(id, name, role, host string, sshPort int, user, password string) (*models.ServerNode, error) {
	// If password is provided, verify SSH; if blank, allow adding a manually-installed agent by IP!
	pct := 15
	state := "SSH_VERIFIED"
	logMsg := fmt.Sprintf("[15%%] SSH verified to %s@%s:%d. Click Deploy or run agent on port 9444.", user, host, sshPort)

	if password != "" {
		client, err := dialSSH(host, sshPort, user, password)
		if err != nil {
			return nil, fmt.Errorf("SSH connection failed: %w", err)
		}
		_ = client.Close()
	} else {
		pct = 100
		state = "READY"
		logMsg = fmt.Sprintf("[100%%] Added manually-installed agent node at %s:9444.", host)
	}

	node := &models.ServerNode{
		ID:          id,
		Name:        name,
		Role:        role,
		Host:        host,
		SSHPort:     sshPort,
		SSHUser:     user,
		AgentPort:   9444,
		Connected:   true,
		DeployState: state,
		DeployPct:   pct,
		DeployLogs:  []string{logMsg},
		UpdatedAt:   time.Now().UTC(),
	}

	nm.mu.Lock()
	nm.nodes[id] = node
	nm.passwords[id] = password
	nm.mu.Unlock()
	return node, nil
}

func (nm *NodeManager) logStep(id, state string, pct int, msg string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if n, ok := nm.nodes[id]; ok {
		n.DeployState = state
		n.DeployPct = pct
		n.DeployLogs = append(n.DeployLogs, fmt.Sprintf("[%d%%] %s", pct, msg))
		n.UpdatedAt = time.Now().UTC()
	}
}

func (nm *NodeManager) DeployAgentAsync(id, hubIP, token string) {
	go func() {
		nm.mu.RLock()
		node, ok := nm.nodes[id]
		pass := nm.passwords[id]
		nm.mu.RUnlock()
		if !ok || id == "local-s1" {
			return
		}

		nm.logStep(id, "DEPLOYING", 20, "Connecting to remote server via SSH...")
		client, err := dialSSH(node.Host, node.SSHPort, node.SSHUser, pass)
		if err != nil {
			nm.logStep(id, "ERROR", 15, "ERROR: SSH dial failed: "+err.Error())
			return
		}
		defer client.Close()

		nm.logStep(id, "DEPLOYING", 40, "Locating pre-compiled sahand-agent binary on Hub...")
		binPath := "/opt/sahand-matrix/bin/sahand-agent"
		if _, err := os.Stat(binPath); err != nil {
			cmd := exec.Command("/usr/local/go/bin/go", "build", "-ldflags=-s -w", "-o", "/opt/sahand-matrix/bin/sahand-agent", "./cmd/sahand-agent")
			cmd.Dir = "/opt/sahand-matrix/src"
			_ = cmd.Run()
		}
		binBytes, err := os.ReadFile(binPath)
		if err != nil {
			nm.logStep(id, "ERROR", 15, "ERROR: Binary not found at "+binPath)
			return
		}

		nm.logStep(id, "DEPLOYING", 65, fmt.Sprintf("Uploading sahand-agent (%d KB) over SSH...", len(binBytes)/1024))
		_ = runSSHCommand(client, "systemctl stop sahand-agent 2>/dev/null || true; mkdir -p /opt/sahand-matrix/bin", nil)
		if err := runSSHCommand(client, "cat > /opt/sahand-matrix/bin/sahand-agent && chmod +x /opt/sahand-matrix/bin/sahand-agent", bytes.NewReader(binBytes)); err != nil {
			nm.logStep(id, "ERROR", 15, "ERROR: Upload failed: "+err.Error())
			return
		}

		nm.logStep(id, "DEPLOYING", 85, "Starting systemd service on port 9444...")
		unitCmd := fmt.Sprintf(`cat << 'EOF' > /etc/systemd/system/sahand-agent.service
[Unit]
Description=Sahand Real Packet Sniffer Agent (%s)
After=network.target

[Service]
Type=simple
ExecStart=/opt/sahand-matrix/bin/sahand-agent --role %s --id %s --peer %s --token %s --listen :9444
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable sahand-agent --now`, node.Role, node.Role, node.ID, hubIP, token)

		if err := runSSHCommand(client, unitCmd, nil); err != nil {
			nm.logStep(id, "ERROR", 15, "ERROR: Service start failed: "+err.Error())
			return
		}

		nm.logStep(id, "READY", 100, fmt.Sprintf("SUCCESS! Agent active at http://%s:9444/", node.Host))
	}()
}

func dialSSH(host string, port int, user, password string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
}

func runSSHCommand(client *ssh.Client, cmd string, stdin *bytes.Reader) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = stdin
	}
	return sess.Run(cmd)
}
