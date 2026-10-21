//

package fingerprint

import "regexp"

var bannerProtocols = map[string]bool{
	"ssh":    true,
	"http":   true,
	"ftp":    true,
	"smtp":   true,
	"pop3":   true,
	"imapv4": true,
	"snmp":   true,
}

func IsBannerProtocol(cluster string) bool { return bannerProtocols[cluster] }

var (
	reSSH        = regexp.MustCompile(`^SSH-\d+\.\d+-(\S+)`)
	reHTTPServer = regexp.MustCompile(`(?im)^Server:\s*([^\r\n]+)`)
	reHTTPStatus = regexp.MustCompile(`^HTTP/\d\.\d\s+\d{3}\s+([^\r\n]+)`)
	reFTP        = regexp.MustCompile(`^220[^\r\n]*`)
	reSMTPID     = regexp.MustCompile(`(?i)(Postfix|Sendmail|Exim|OpenSMTPD|Dovecot)`)
	reSMTPGreet  = regexp.MustCompile(`^220\s+([^\r\n]+)`)
	rePOP3       = regexp.MustCompile(`^\+OK\s*([^\r\n]*)`)
	reIMAP       = regexp.MustCompile(`^\*\s+OK\s*([^\r\n]*)`)
	rePrintRun   = regexp.MustCompile(`[\x20-\x7e]{8,}`)
)

func extractSSH(resp []byte) string {
	if m := reSSH.FindSubmatch(resp); m != nil {
		return string(m[1])
	}
	return ""
}

func extractHTTP(resp []byte) string {
	if m := reHTTPServer.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[1]))
	}
	if m := reHTTPStatus.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[1]))
	}
	return ""
}

func extractFTP(resp []byte) string {
	if m := reFTP.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[0])[3:]) // Response identification metadata.
	}
	return ""
}

func extractSMTP(resp []byte) string {
	if m := reSMTPID.FindSubmatch(resp); m != nil {
		return string(m[1])
	}
	if m := reSMTPGreet.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[1]))
	}
	return ""
}

func extractPOP3(resp []byte) string {
	if m := rePOP3.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[1]))
	}
	return ""
}

func extractIMAP(resp []byte) string {
	if m := reIMAP.FindSubmatch(resp); m != nil {
		return trimASCII(string(m[1]))
	}
	return ""
}

func extractSNMP(resp []byte) string {
	runs := rePrintRun.FindAll(resp, -1)
	if len(runs) == 0 {
		return ""
	}
	best := runs[0]
	for _, r := range runs[1:] {
		if len(r) > len(best) {
			best = r
		}
	}
	s := trimASCII(string(best))
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func ExtractVersion(cluster string, resp []byte) (version string, ok bool) {
	if !bannerProtocols[cluster] || len(resp) == 0 {
		return "", false
	}
	var v string
	switch cluster {
	case "ssh":
		v = extractSSH(resp)
	case "http":
		v = extractHTTP(resp)
	case "ftp":
		v = extractFTP(resp)
	case "smtp":
		v = extractSMTP(resp)
	case "pop3":
		v = extractPOP3(resp)
	case "imapv4":
		v = extractIMAP(resp)
	case "snmp":
		v = extractSNMP(resp)
	}
	if v == "" {
		return "", false
	}
	return v, true
}

func trimASCII(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
