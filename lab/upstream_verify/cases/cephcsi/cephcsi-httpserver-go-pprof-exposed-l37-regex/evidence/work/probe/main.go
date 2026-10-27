package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	runtime_pprof "runtime/pprof"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ceph/ceph-csi/internal/util/log"
)

// verbatim: internal/util/httpserver.go:17-21
func ValidateURL(c *Config) error {
	_, err := url.Parse(c.MetricsPath)

	return err
}

// verbatim: internal/util/httpserver.go:24-33
func StartMetricsServer(c *Config) {
	addr := net.JoinHostPort(c.MetricsIP, strconv.Itoa(c.MetricsPort))
	http.Handle(c.MetricsPath, promhttp.Handler())

	//nolint:gosec // TODO: add support for passing timeouts
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.FatalLogMsg("failed to listen on address %v: %s", addr, err)
	}
}

// verbatim: internal/util/httpserver.go:35-38
func addPath(name string, handler http.Handler) {
	http.Handle(name, handler)
	log.DebugLogMsg("DEBUG: registered profiling handler on /debug/pprof/%s\n", name)
}

// verbatim: internal/util/httpserver.go:41-53
func EnableProfiling() {
	for _, profile := range runtime_pprof.Profiles() {
		name := profile.Name()
		handler := pprof.Handler(name)
		addPath(name, handler)
	}

	// static profiles as listed in net/http/pprof/pprof.go:init()
	addPath("cmdline", http.HandlerFunc(pprof.Cmdline))
	addPath("profile", http.HandlerFunc(pprof.Profile))
	addPath("symbol", http.HandlerFunc(pprof.Symbol))
	addPath("trace", http.HandlerFunc(pprof.Trace))
}

// verbatim: internal/util/util.go:99-174
type Config struct {
	Vtype           string // driver type [rbd|cephfs|liveness|controller]
	Endpoint        string // CSI endpoint
	DriverName      string // name of the driver
	DriverNamespace string // namespace in which driver is deployed
	NodeID          string // node id
	InstanceID      string // unique ID distinguishing this instance of Ceph CSI
	PluginPath      string // location of cephcsi plugin
	StagingPath     string // location of cephcsi staging path
	DomainLabels    string // list of domain labels to read from the node
	// metrics related flags
	MetricsPath string // path of prometheus endpoint where metrics will be available
	MetricsIP   string // TCP port for liveness/ metrics requests

	// CSI-Addons endpoint
	CSIAddonsEndpoint string

	// Cluster name
	ClusterName string

	// mount option related flags
	KernelMountOptions string // Comma separated string of mount options accepted by cephfs kernel mounter
	FuseMountOptions   string // Comma separated string of mount options accepted by ceph-fuse mounter

	// RbdHardMaxCloneDepth is the hard limit for maximum number of nested volume clones that are taken before a flatten
	// occurs
	RbdHardMaxCloneDepth uint

	// RbdSoftMaxCloneDepth is the soft limit for maximum number of nested volume clones that are taken before a flatten
	// occurs
	RbdSoftMaxCloneDepth uint

	// MaxSnapshotsOnImage represents the maximum number of snapshots allowed
	// on rbd image without flattening, once the limit is reached cephcsi will
	// start flattening the older rbd images to allow more snapshots
	MaxSnapshotsOnImage uint

	// MinSnapshotsOnImage represents the soft limit for maximum number of
	// snapshots allowed on rbd image without flattening, once the soft limit is
	// reached cephcsi will start flattening the older rbd images.
	MinSnapshotsOnImage uint

	PidLimit    int           // PID limit to configure through cgroups")
	MetricsPort int           // TCP port for liveness/grpc metrics requests
	PollTime    time.Duration // time interval in seconds between each poll
	PoolTimeout time.Duration // probe timeout in seconds
	// Log interval for slow GRPC calls. Calls that outlive their context deadline
	// are considered slow.
	LogSlowOpInterval time.Duration

	AutoMaxProcs bool // configure GOMAXPROCS with automaxprocs

	EnableProfiling    bool // flag to enable profiling
	IsControllerServer bool // if set to true start provisioner server
	IsNodeServer       bool // if set to true start node server
	Version            bool // cephcsi version

	// SkipForceFlatten is set to false if the kernel supports mounting of
	// rbd image or the image chain has the deep-flatten feature.
	SkipForceFlatten bool

	// enable fencing of nodes during non-graceful shutdowns.
	EnableFencing bool

	// cephfs related flags
	ForceKernelCephFS    bool   // force to use the ceph kernel client even if the kernel is < 4.17
	RadosNamespaceCephFS string // RadosNamespace used to store CSI specific objects and keys
	SetMetadata          bool   // Deprecated: has no effect, metadata is always set on volumes

	// Read affinity related options
	EnableReadAffinity  bool   // enable OSD read affinity.
	CrushLocationLabels string // list of CRUSH location labels to read from the node.

	// FeatureGates is a comma-separated list of key=bool pairs (e.g., SlowGRPCRestart=false).
	FeatureGates string
}

var _ = log.DebugLogMsg

func main() {
	port := os.Getenv("CEPH_HTTP_PORT")
	// The pinned file imports net/http/pprof non-blank (line 6): its init() registers
	// /debug/pprof/* on the DEFAULT mux, which StartMetricsServer serves verbatim.
	// (EnableProfiling/addPath itself registers patterns without a leading "/" and
	// panics on Go >= 1.22 ServeMux pattern rules; the exposure does not depend on it.)
	_ = EnableProfiling
	_ = addPath
	_ = ValidateURL
	go StartMetricsServer(&Config{
		MetricsIP:   "127.0.0.1",
		MetricsPort: mustAtoi(port),
		MetricsPath: "/metrics",
	})
	base := "http://127.0.0.1:" + port
	for _, path := range []string{"/debug/pprof/cmdline", "/debug/pprof/heap?debug=1", "/metrics", "/debug/pprof/"} {
		deadline := time.Now().Add(20 * time.Second)
		for {
			resp, err := http.Get(base + path)
			if err == nil {
				fmt.Printf("GET %s -> %d len=%d\n", path, resp.StatusCode, resp.ContentLength)
				resp.Body.Close()
				break
			}
			if time.Now().After(deadline) {
				fmt.Printf("GET %s -> err %v\n", path, err)
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
