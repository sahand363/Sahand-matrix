package hub

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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
	// Register Primary Local Server (S1) by default
	nm.nodes["local-s1"] = &models.ServerNode{
		ID:         "local-s1",
		Name:       "Primary Server (Local Hub)",
		Role:       "iran",
		Host:       localIP,
		SSHPort:    22,
		SSHUser:    "root",
		AgentPort:  9444,
		Connected:  true,
		Capturing:  false, // Stopped by default
		DeployPct:  100,
		DeployLogs: []string{"[100%] Local sniffer ready (Idle / Stopped)."},
		UpdatedAt:  time.Now().UTC(),
	}
	return nm
}

func (nm *NodeManager) ListNodes() []*models.ServerNode {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	var list []*models.ServerNode
	for _, n := range nm.nodes {
		cp := *n
		list = append(list, &cp)
	}
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

// AddAndVerifySSH tests SSH credentials and adds the server card.
func (nm *NodeManager) AddAndVerifySSH(id, name, role, host string, sshPort int, user, password string) (*models.ServerNode, error) {
	client, err := dialSSH(host, sshPort, user, password)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}
	_ = client.Close()

	node := &models.ServerNode{
		ID:         id,
		Name:       name,
		Role:       role,
		Host:       host,
		SSHPort:    sshPort,
		SSHUser:    user,
		AgentPort:  9444,
		Connected:  true,
		Capturing:  false,
		DeployPct:  10,
		DeployLogs: []string{fmt.Sprintf("[10%%] SSH verified to %s@%s:%d. Ready to deploy sahand-agent.", user, host, sshPort)},
		UpdatedAt:  time.Now().UTC(),
	}

	nm.mu.Lock()
	nm.nodes[id] = node
	nm.passwords[id] = password
	nm.mu.Unlock()
	return node, nil
}

func (nm *NodeManager) logStep(id string, pct int, msg string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if n, ok := nm.nodes[id]; ok {
		n.DeployPct = pct
		n.DeployLogs = append(n.DeployLogs, fmt.Sprintf("[%d%%] %s", pct, msg))
		n.UpdatedAt = time.Now().UTC()
	}
}

// DeployAgentAsync streams the pre-compiled sahand-agent binary over SSH and starts the systemd service.
func (nm *NodeManager) DeployAgentAsync(id, hubIP, token string) {
	go func() {
		nm.mu.RLock()
		node, ok := nm.nodes[id]
		pass := nm.passwords[id]
		nm.mu.RUnlock()
		if !ok {
			return
		}

		nm.logStep(id, 20, "Connecting to remote server via SSH...")
		client, err := dialSSH(node.Host, node.SSHPort, node.SSHUser, pass)
		if err != nil {
			nm.logStep(id, 0, "ERROR: SSH dial failed: "+err.Error())
			return
		}
		defer client.Close()

		nm.logStep(id, 35, "Preparing sahand-agent binary on Hub (no Go required on remote server)...")
		binPath := "/opt/sahand-matrix/bin/sahand-agent"
		if _, err := os.Stat(binPath); err != nil {
			_ = exec.Command("go", "build", "-ldflags=-s -w", "-o", "/tmp/sahand-agent", "./cmd/sahand-agent").Run()
			binPath = "/tmp/sahand-agent"
		}
		binBytes, err := os.ReadFile(binPath)
		if err != nil {
			nm.logStep(id, 0, "ERROR: Could not read local sahand-agent binary: "+err.Error())
			return
		}

		nm.logStep(id, 60, fmt.Sprintf("Uploading sahand-agent (%d KB) over SSH pipe...", len(binBytes)/1024))
		_ = runSSHCommand(client, "systemctl stop sahand-agent 2>/dev/null || true; mkdir -p /opt/sahand-matrix/bin", nil)
		if err := runSSHCommand(client, "cat > /opt/sahand-matrix/bin/sahand-agent && chmod +x /opt/sahand-matrix/bin/sahand-agent", bytes.NewReader(binBytes)); err != nil {
			nm.logStep(id, 0, "ERROR: Binary transfer failed: "+err.Error())
			return
		}

		nm.logStep(id, 85, "Configuring systemd service & local 3-window web view on port 9444...")
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
			nm.logStep(id, 0, "ERROR: Service start failed: "+err.Error())
			return
		}

		nm.logStep(id, 100, fmt.Sprintf("SUCCESS! Agent active. Remote 3-Window View: http://%s:9444/", node.Host))
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
