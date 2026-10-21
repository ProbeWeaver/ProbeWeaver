// Package fuzzing contains the zgrab2 Module implementation for ML-enhanced fingerprint detection.
package fuzzing

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	fingerprint "github.com/zmap/zgrab2/lib/fingerprint"
)

// Default confidence threshold — updated by deploy_model.py from config.py
var confidenceThreshold = 0.7

var memberConfidenceThreshold = 0.6

// ScanResults is the output of the scan.
type ScanResults struct {
	Response string `json:"response,omitempty"`

	Service string                  `json:"service,omitempty"`
	Source  string                  `json:"source,omitempty"`
	Matches []fingerprint.MatchInfo `json:"matches,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Ambiguous  bool     `json:"ambiguous,omitempty"`

	// ML model prediction (Layer 2 diagnostics; always populated when --use-ml).
	MLService    string  `json:"ml_service,omitempty"`
	MLConfidence float64 `json:"ml_confidence,omitempty"`
	MLReliable   bool    `json:"ml_reliable,omitempty"`

	// Stage B: member code rules → optional RF (--use-ml) → unknown.
	Member           string  `json:"member,omitempty"`
	MemberSource     string  `json:"member_source,omitempty"` // member_code / member_rf / unknown
	MemberConfidence float64 `json:"member_confidence,omitempty"`

	// Stage C (version, only when member known AND banner protocol): extractor → unknown.
	Version       string `json:"version,omitempty"`
	VersionSource string `json:"version_source,omitempty"` // extractor / unknown

	// TLS
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
	// Explicit execution facts; TLS records are not application probes.
	TLSHandshakeStatus      string `json:"tls_handshake_status"`
	ApplicationPayloads     int    `json:"application_payloads"`
	ApplicationPayloadBytes int    `json:"application_payload_bytes"`
	ConnectionsEstablished  int    `json:"connections_established"`
}

// Flags are the fuzzing-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`
	zgrab2.UDPFlags  `group:"UDP Options"`
	Verbose          bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	Payload          string `long:"payload" description:"Hex string to send to the target"`
	RulesFile        string `long:"rules" description:"Path to the T3 baseline rule JSON (nmap/hand 4-form invariants; tried last, after Agent code rules and ML both miss)"`
	UseML            bool   `long:"use-ml" description:"Enable ML model prediction (RandomForest). Default: off (baseline mode)"`
	UseUDP           bool   `long:"udp" description:"Use UDP instead of TCP for the connection"`
	UseTLS           bool   `long:"tls" description:"Perform TLS handshake after connecting (implicit TLS)"`
}

// Module implements the zgrab2.Module interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config     *Flags
	ruleEngine *fingerprint.RuleEngine // Response identification metadata.
	// Member rules and opt-in RF are compiled in; no runtime member JSON engine.
}

// RegisterModule registers the fuzzing zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("fuzzing", "ML-enhanced fuzzing with fingerprint matching", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

func (m *Module) Description() string {
	return "Sends a user-defined payload and identifies the service via a 3-tier cascade (Agent code rules -> ML -> nmap/hand rules)"
}

func (f *Flags) Validate(args []string) error {
	if f.UseTLS && f.UseUDP {
		return fmt.Errorf("--tls is TCP-only; cannot combine with --udp")
	}
	if f.Payload == "" {
		return fmt.Errorf("payload is required (e.g., --payload=0000)")
	}
	if _, err := hex.DecodeString(f.Payload); err != nil {
		return fmt.Errorf("invalid hex payload: %v", err)
	}
	if f.RulesFile != "" {
		if _, err := os.Stat(f.RulesFile); os.IsNotExist(err) {
			return fmt.Errorf("rules file does not exist: %s", f.RulesFile)
		}
	}
	return nil
}

func (f *Flags) Help() string {
	return ""
}

func (s *Scanner) Protocol() string {
	return "fuzzing"
}

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f

	if s.config.RulesFile != "" {
		engine, err := fingerprint.LoadRules(s.config.RulesFile)
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		s.ruleEngine = engine
		log.Infof("Loaded %d T3 baseline rules from %s", engine.Len(), s.config.RulesFile)
	}

	// Stage B member rules/RF need no runtime loading.

	return nil
}

func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (s *Scanner) GetName() string {
	return s.config.Name
}

func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Scan performs: Connect -> Send Payload -> Read Response -> 3-tier identification cascade
func (s *Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var results ScanResults
	results.TLSHandshakeStatus = "not_requested"
	if s.config.UseTLS {
		results.TLSHandshakeStatus = "not_attempted"
	}

	// 1. Establish Connection (TCP or UDP based on --udp flag)
	var conn net.Conn
	var err error
	if s.config.UseUDP {
		conn, err = t.OpenUDP(&s.config.BaseFlags, &s.config.UDPFlags)
	} else {
		conn, err = t.Open(&s.config.BaseFlags)
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("error establishing connection: %w", err)
	}
	results.ConnectionsEstablished = 1
	defer conn.Close()

	// 1b. TLS handshake (implicit TLS, if --tls is set, TCP only)
	tlsHandshakeOK := false
	if s.config.UseTLS {
		tlsConn, err := s.config.TLSFlags.GetTLSConnection(conn)
		if err != nil {
			results.TLSHandshakeStatus = "setup_error"
			return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("error setting up TLS connection: %w", err)
		}
		results.TLSLog = tlsConn.GetLog()
		if err := tlsConn.Handshake(); err != nil {
			results.TLSHandshakeStatus = "failed"
			return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("TLS handshake failed: %w", err)
		}
		results.TLSHandshakeStatus = "succeeded"
		conn = tlsConn
		tlsHandshakeOK = true
	}

	// 2. Prepare Payload
	payload, err := hex.DecodeString(s.config.Payload)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("error decoding payload: %w", err)
	}

	// 3. Send Payload
	nWritten, writeErr := conn.Write(payload)
	results.ApplicationPayloadBytes = nWritten
	if nWritten > 0 {
		results.ApplicationPayloads = 1
	}
	if writeErr != nil {
		return zgrab2.TryGetScanStatus(writeErr), &results, fmt.Errorf("error sending data: %w", writeErr)
	}

	// 4. Read Response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if !tlsHandshakeOK && err != net.Error(nil) && err.Error() != "EOF" {
			return zgrab2.TryGetScanStatus(err), &results, fmt.Errorf("error reading response: %w", err)
		}
	}

	actualResponse := buf[:n]
	results.Response = hex.EncodeToString(actualResponse)

	if n == 0 && !tlsHandshakeOK {
		return zgrab2.SCAN_IO_TIMEOUT, &results, fmt.Errorf("no response received from server")
	}

	// 5. Multi-granularity cascade: Stage A cluster → Stage B member → Stage C version.
	var features []float64
	if s.config.UseML {
		features = fingerprint.ExtractFeaturesWithContext(payload, actualResponse)
	}

	clusterKnown := false
	codeMatches := fingerprint.MatchAllCode(actualResponse)

	// Tier 1: Agent code (Tier==1) + 4-form specific (llm/deterministic)
	var t1 []fingerprint.MatchInfo
	for _, m := range codeMatches {
		if m.Tier == 1 {
			t1 = append(t1, m)
		}
	}
	if s.ruleEngine != nil {
		t1 = append(t1, s.ruleEngine.MatchAllSpecific(actualResponse)...)
	}
	t1 = dedupSortMatches(t1)
	if len(t1) > 0 {
		results.Matches = t1
		results.Service = t1[0].Service
		results.Source = t1[0].Source
		clusterKnown = true
	} else if s.config.UseML {
		mlResult := fingerprint.PredictServiceWithConfidence(features, confidenceThreshold)
		results.MLService = mlResult.Service
		results.MLConfidence = mlResult.Confidence
		results.MLReliable = mlResult.IsReliable
		if mlResult.IsReliable {
			results.Matches = []fingerprint.MatchInfo{{Service: mlResult.Service, Source: "rf", Tier: 2}}
			results.Service = mlResult.Service
			results.Source = "rf"
			clusterKnown = true
		}
	}
	if !clusterKnown {
		var t3 []fingerprint.MatchInfo
		if s.ruleEngine != nil {
			t3 = append(t3, s.ruleEngine.MatchAllBaseline(actualResponse)...)
		}
		for _, m := range codeMatches {
			if m.Tier == 3 {
				t3 = append(t3, m)
			}
		}
		t3 = dedupSortMatches(t3)
		results.Matches = t3
		if len(t3) > 0 {
			results.Service = t3[0].Service
			results.Source = t3[0].Source
			clusterKnown = true
		} else {
			results.Source = "unknown"
		}
	}
	results.Candidates = candidateServices(results.Matches)
	results.Ambiguous = len(results.Candidates) > 1

	// Stage B remains nested. Do not refine an arbitrary service when Stage A
	// returned several candidates. --use-ml opts into the admitted member RFs.
	if clusterKnown && results.Service != "" && !results.Ambiguous {
		results.Member, results.MemberSource, results.MemberConfidence = fingerprint.ResolveMember(
			results.Service, actualResponse, features, s.config.UseML, memberConfidenceThreshold)
	}

	// --- Stage C: version (only if member known AND banner protocol) ---
	if results.Member != "" && fingerprint.IsBannerProtocol(results.Service) {
		if v, ok := fingerprint.ExtractVersion(results.Service, actualResponse); ok {
			results.Version = v
			results.VersionSource = "extractor"
		} else {
			results.VersionSource = "unknown"
		}
	}

	if !clusterKnown && tlsHandshakeOK {
		results.Service = "tls"
		results.Source = "tls"
		results.Matches = []fingerprint.MatchInfo{{Service: "tls", Source: "tls", Tier: 0}}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}

func sourceSubPriority(source string) int {
	switch source {
	case "code":
		return 0
	case "llm":
		return 1
	case "deterministic":
		return 2
	case "rf":
		return 3
	case "nmap":
		return 4
	case "hand":
		return 5
	case "hand_code":
		return 6
	default:
		return 7
	}
}

func dedupSortMatches(in []fingerprint.MatchInfo) []fingerprint.MatchInfo {
	if len(in) == 0 {
		return nil
	}
	best := make(map[string]fingerprint.MatchInfo, len(in))
	for _, m := range in {
		if cur, ok := best[m.Service]; !ok || sourceSubPriority(m.Source) < sourceSubPriority(cur.Source) {
			best[m.Service] = m
		}
	}
	out := make([]fingerprint.MatchInfo, 0, len(best))
	for _, m := range best {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := sourceSubPriority(out[i].Source), sourceSubPriority(out[j].Source)
		if si != sj {
			return si < sj
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func candidateServices(matches []fingerprint.MatchInfo) []string {
	seen := make(map[string]bool)
	var out []string
	for _, match := range matches {
		for _, service := range fingerprint.IdentificationCandidates(match.Service) {
			if service == "" || seen[service] {
				continue
			}
			seen[service] = true
			out = append(out, service)
		}
	}
	sort.Strings(out)
	return out
}
