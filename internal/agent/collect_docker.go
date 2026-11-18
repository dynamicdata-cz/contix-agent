package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

/* ---------------- containers (Docker / Podman Engine API, read-only GET) ---------------- */

// Container engine sockets tried in order. Podman serves a Docker-compatible API.
var engineSockets = []string{"/run/docker.sock", "/var/run/docker.sock", "/run/podman/podman.sock"}

// errNoEngine means no container engine socket was found (the modules stay empty, no error).
var errNoEngine = errors.New("no container engine")

// engineSocket returns the first existing engine socket.
func (c *Collector) engineSocket() string {
	for _, p := range engineSockets {
		if fi, err := os.Stat(c.path(p)); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

// engineGet performs a read-only GET on the container engine API. Tests replace it via EngineGet.
func (c *Collector) engineGet(ctx context.Context, path string) ([]byte, error) {
	if c.EngineGet != nil {
		return c.EngineGet(ctx, path)
	}
	sock := c.engineSocket()
	if sock == "" {
		return nil, errNoEngine
	}
	full := c.path(sock)
	cl := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", full)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine %s: HTTP %d", path, resp.StatusCode)
	}
	return b, nil
}

// ContainerMount is a volume or bind mount (never file contents).
type ContainerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// Container is a container with its security-relevant settings. Environment variables,
// command lines and labels (apart from the compose project/service) are never sent.
type Container struct {
	Name           string           `json:"name"`
	ID             string           `json:"id"`
	Image          string           `json:"image"`
	ImageID        string           `json:"imageId,omitempty"`
	State          string           `json:"state"`
	Health         string           `json:"health,omitempty"`
	Created        string           `json:"created,omitempty"`
	StartedAt      string           `json:"startedAt,omitempty"`
	RestartCount   int              `json:"restartCount,omitempty"`
	Restart        string           `json:"restart,omitempty"`
	User           string           `json:"user"`
	Privileged     bool             `json:"privileged"`
	ReadOnlyRootfs bool             `json:"readOnlyRootfs"`
	NoNewPrivs     bool             `json:"noNewPrivileges"`
	NetworkMode    string           `json:"networkMode,omitempty"`
	PidMode        string           `json:"pidMode,omitempty"`
	IpcMode        string           `json:"ipcMode,omitempty"`
	UsernsMode     string           `json:"usernsMode,omitempty"`
	CapAdd         []string         `json:"capAdd,omitempty"`
	CapDrop        []string         `json:"capDrop,omitempty"`
	SecurityOpt    []string         `json:"securityOpt,omitempty"`
	AppArmor       string           `json:"apparmor,omitempty"`
	Devices        []string         `json:"devices,omitempty"`
	Ports          []string         `json:"ports,omitempty"`
	Mounts         []ContainerMount `json:"mounts,omitempty"`
	MemoryLimit    int64            `json:"memoryLimit,omitempty"`
	CPULimit       float64          `json:"cpuLimit,omitempty"`
	PidsLimit      int64            `json:"pidsLimit,omitempty"`
	Healthcheck    bool             `json:"healthcheck"`
	Project        string           `json:"project,omitempty"`
	Service        string           `json:"service,omitempty"`
}

type inspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Image   string `json:"Image"`
	State   struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount    int    `json:"RestartCount"`
	AppArmorProfile string `json:"AppArmorProfile"`
	Config          struct {
		Image       string            `json:"Image"`
		User        string            `json:"User"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		UsernsMode     string   `json:"UsernsMode"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
		PidsLimit      *int64   `json:"PidsLimit"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Devices []struct {
			PathOnHost string `json:"PathOnHost"`
		} `json:"Devices"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// containerFromInspect maps an engine inspect result to the sent item.
func containerFromInspect(in inspect) Container {
	c := Container{
		Name:           trunc(strings.TrimPrefix(in.Name, "/"), 255),
		ID:             shortID(in.ID),
		Image:          trunc(in.Config.Image, 500),
		ImageID:        shortID(in.Image),
		State:          in.State.Status,
		Created:        in.Created,
		RestartCount:   in.RestartCount,
		Restart:        in.HostConfig.RestartPolicy.Name,
		User:           trunc(in.Config.User, 100),
		Privileged:     in.HostConfig.Privileged,
		ReadOnlyRootfs: in.HostConfig.ReadonlyRootfs,
		NetworkMode:    in.HostConfig.NetworkMode,
		PidMode:        in.HostConfig.PidMode,
		IpcMode:        in.HostConfig.IpcMode,
		UsernsMode:     in.HostConfig.UsernsMode,
		CapAdd:         in.HostConfig.CapAdd,
		CapDrop:        in.HostConfig.CapDrop,
		AppArmor:       in.AppArmorProfile,
		MemoryLimit:    in.HostConfig.Memory,
		CPULimit:       float64(in.HostConfig.NanoCpus) / 1e9,
		Project:        in.Config.Labels["com.docker.compose.project"],
		Service:        in.Config.Labels["com.docker.compose.service"],
	}
	if in.State.Status == "running" {
		c.StartedAt = in.State.StartedAt
	}
	if in.State.Health != nil {
		c.Health = in.State.Health.Status
	}
	if in.HostConfig.PidsLimit != nil && *in.HostConfig.PidsLimit > 0 {
		c.PidsLimit = *in.HostConfig.PidsLimit
	}
	hc := in.Config.Healthcheck
	c.Healthcheck = hc != nil && len(hc.Test) > 0 && hc.Test[0] != "NONE"
	for _, o := range in.HostConfig.SecurityOpt {
		o = trunc(o, 200)
		c.SecurityOpt = append(c.SecurityOpt, o)
		if o == "no-new-privileges" || o == "no-new-privileges:true" || o == "no-new-privileges=true" {
			c.NoNewPrivs = true
		}
	}
	for _, d := range in.HostConfig.Devices {
		c.Devices = append(c.Devices, trunc(d.PathOnHost, 200))
	}
	for port, binds := range in.NetworkSettings.Ports {
		for _, b := range binds {
			if b.HostPort == "" {
				continue
			}
			ip := b.HostIP
			if ip == "" {
				ip = "0.0.0.0"
			}
			c.Ports = append(c.Ports, net.JoinHostPort(ip, b.HostPort)+"->"+port)
		}
	}
	sort.Strings(c.Ports)
	for _, m := range in.Mounts {
		src := m.Source
		if m.Type == "volume" && m.Name != "" {
			src = m.Name
		}
		c.Mounts = append(c.Mounts, ContainerMount{Type: m.Type, Source: trunc(src, 300), Destination: trunc(m.Destination, 300), RW: m.RW})
	}
	sort.Slice(c.Mounts, func(i, j int) bool { return c.Mounts[i].Destination < c.Mounts[j].Destination })
	return c
}

func (c *Collector) containers(ctx context.Context, s *Snapshot) error {
	b, err := c.engineGet(ctx, "/containers/json?all=1")
	if errors.Is(err, errNoEngine) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	if len(list) > 2000 {
		list = list[:2000]
	}
	for _, it := range list {
		raw, err := c.engineGet(ctx, "/containers/"+it.ID+"/json")
		if err != nil {
			continue // removed in the meantime
		}
		var in inspect
		if json.Unmarshal(raw, &in) != nil {
			continue
		}
		ct := containerFromInspect(in)
		s.put(ModContainers, ct.Name, ct)
	}
	return nil
}

// Image is a local container image.
type Image struct {
	ID      string   `json:"id"`
	Tags    []string `json:"tags,omitempty"`
	Created string   `json:"created,omitempty"`
	Size    int64    `json:"size,omitempty"`
}

func (c *Collector) images(ctx context.Context, s *Snapshot) error {
	b, err := c.engineGet(ctx, "/images/json")
	if errors.Is(err, errNoEngine) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Created  int64    `json:"Created"`
		Size     int64    `json:"Size"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	if len(list) > 5000 {
		list = list[:5000]
	}
	for _, it := range list {
		im := Image{ID: shortID(it.ID), Size: it.Size}
		for _, t := range it.RepoTags {
			if t != "<none>:<none>" && len(im.Tags) < 20 {
				im.Tags = append(im.Tags, trunc(t, 300))
			}
		}
		if it.Created > 0 {
			im.Created = time.Unix(it.Created, 0).UTC().Format(time.RFC3339)
		}
		s.put(ModImages, im.ID, im)
	}
	return nil
}

// Engine describes the container engine and its security posture.
type Engine struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Socket          string   `json:"socket"`
	SocketMode      string   `json:"socketMode,omitempty"`
	SocketGroup     string   `json:"socketGroup,omitempty"`
	GroupMembers    []string `json:"groupMembers,omitempty"`
	SecurityOptions []string `json:"securityOptions,omitempty"`
	Rootless        bool     `json:"rootless"`
	UsernsRemap     bool     `json:"usernsRemap"`
	LiveRestore     bool     `json:"liveRestore"`
	LoggingDriver   string   `json:"loggingDriver,omitempty"`
	CgroupVersion   string   `json:"cgroupVersion,omitempty"`
	// From /etc/docker/daemon.json and the service command line (selected settings only).
	ICC             *bool    `json:"icc,omitempty"`
	NoNewPrivileges bool     `json:"noNewPrivileges"`
	UserlandProxy   *bool    `json:"userlandProxy,omitempty"`
	TCPHosts        []string `json:"tcpHosts,omitempty"`
	TLSVerify       bool     `json:"tlsVerify"`
}

// groupMembers returns the members of a group from /etc/group.
func (c *Collector) groupMembers(name string) (gid string, members []string) {
	b, err := c.read("/etc/group")
	if err != nil {
		return "", nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[0] == name {
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					members = append(members, m)
				}
			}
			return f[2], members
		}
	}
	return "", nil
}

func (c *Collector) engine(ctx context.Context, s *Snapshot) error {
	vb, err := c.engineGet(ctx, "/version")
	if errors.Is(err, errNoEngine) {
		return nil
	}
	if err != nil {
		return err
	}
	var ver struct {
		Version    string `json:"Version"`
		Components []struct {
			Name string `json:"Name"`
		} `json:"Components"`
	}
	_ = json.Unmarshal(vb, &ver)
	e := Engine{Name: "docker", Version: trunc(ver.Version, 40), Socket: c.engineSocket()}
	for _, comp := range ver.Components {
		if strings.Contains(strings.ToLower(comp.Name), "podman") {
			e.Name = "podman"
		}
	}
	if strings.Contains(e.Socket, "podman") {
		e.Name = "podman"
	}
	if ib, err := c.engineGet(ctx, "/info"); err == nil {
		var info struct {
			SecurityOptions    []string `json:"SecurityOptions"`
			LiveRestoreEnabled bool     `json:"LiveRestoreEnabled"`
			LoggingDriver      string   `json:"LoggingDriver"`
			CgroupVersion      string   `json:"CgroupVersion"`
		}
		_ = json.Unmarshal(ib, &info)
		for _, o := range info.SecurityOptions {
			e.SecurityOptions = append(e.SecurityOptions, trunc(o, 120))
			if strings.Contains(o, "name=rootless") {
				e.Rootless = true
			}
			if strings.Contains(o, "name=userns") {
				e.UsernsRemap = true
			}
		}
		e.LiveRestore = info.LiveRestoreEnabled
		e.LoggingDriver = trunc(info.LoggingDriver, 40)
		e.CgroupVersion = info.CgroupVersion
	}
	if e.Socket != "" {
		if fi, err := os.Stat(c.path(e.Socket)); err == nil {
			e.SocketMode = fmt.Sprintf("%04o", fi.Mode().Perm())
			if gid := fileGID(fi); gid >= 0 {
				e.SocketGroup = c.groupName(gid)
			}
		}
	}
	grp := e.SocketGroup
	if grp == "" || grp == "root" {
		grp = "docker"
	}
	_, e.GroupMembers = c.groupMembers(grp)
	if b, err := c.read("/etc/docker/daemon.json"); err == nil {
		var d map[string]json.RawMessage
		if json.Unmarshal(b, &d) == nil {
			boolOf := func(k string) *bool {
				var v bool
				if raw, ok := d[k]; ok && json.Unmarshal(raw, &v) == nil {
					return &v
				}
				return nil
			}
			e.ICC = boolOf("icc")
			e.UserlandProxy = boolOf("userland-proxy")
			if v := boolOf("no-new-privileges"); v != nil {
				e.NoNewPrivileges = *v
			}
			if v := boolOf("tlsverify"); v != nil {
				e.TLSVerify = *v
			}
			if raw, ok := d["userns-remap"]; ok && string(raw) != `""` {
				e.UsernsRemap = true
			}
			var hosts []string
			if raw, ok := d["hosts"]; ok && json.Unmarshal(raw, &hosts) == nil {
				for _, h := range hosts {
					if strings.HasPrefix(h, "tcp://") {
						e.TCPHosts = append(e.TCPHosts, trunc(h, 100))
					}
				}
			}
		}
	}
	// -H tcp://… on the service command line (systemd unit or override)
	for _, unit := range []string{"/lib/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service", "/etc/systemd/system/docker.service", "/etc/systemd/system/docker.service.d/override.conf"} {
		b, err := c.read(unit)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "ExecStart=") {
				continue
			}
			f := strings.Fields(l)
			for i, a := range f {
				h := ""
				switch {
				case (a == "-H" || a == "--host") && i+1 < len(f):
					h = f[i+1]
				case strings.HasPrefix(a, "--host="):
					h = strings.TrimPrefix(a, "--host=")
				case strings.HasPrefix(a, "-H="):
					h = strings.TrimPrefix(a, "-H=")
				}
				if strings.HasPrefix(h, "tcp://") {
					e.TCPHosts = append(e.TCPHosts, trunc(h, 100))
				}
				if a == "--tlsverify" {
					e.TLSVerify = true
				}
			}
		}
	}
	sort.Strings(e.TCPHosts)
	s.put(ModEngine, "engine", e)
	return nil
}

// groupName resolves a numeric group id via /etc/group.
func (c *Collector) groupName(gid int) string {
	b, err := c.read("/etc/group")
	if err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 3 && f[2] == strconv.Itoa(gid) {
				return f[0]
			}
		}
	}
	return strconv.Itoa(gid)
}
