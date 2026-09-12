package launchd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"slices"
)

// Job describes a launch agent: the subset of launchd.plist(5) this program uses.
type Job struct {
	Label            string
	ProgramArguments []string
	RunAtLoad        bool
	// KeepAlive asks launchd to keep a job without a user-controlled stop running.
	KeepAlive bool
	// KeepAliveOnFailure asks launchd to restart a process that exits
	// unsuccessfully while leaving deliberate, successful exits alone.
	KeepAliveOnFailure bool
	// ThrottleInterval bounds repeated starts after a persistent failure.
	ThrottleInterval int
	// EnableTransactions lets launchd track the job's XPC transactions, as Apple's own ssh-agent plist does.
	EnableTransactions   bool
	EnvironmentVariables map[string]string
	// SecureSocket makes launchd create a Unix socket for the job and export its
	// path to the domain under Key. The job receives it with launch_activate_socket(Name).
	SecureSocket *SecureSocket
}

// SecureSocket is a launchd-managed listening socket.
type SecureSocket struct {
	Name string
	Key  string
}

const plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
`

// MarshalPlist renders the job as a launchd property list.
func (j Job) MarshalPlist() ([]byte, error) {
	if j.Label == "" {
		return nil, fmt.Errorf("launchd job: label is empty")
	}
	if len(j.ProgramArguments) == 0 {
		return nil, fmt.Errorf("launchd job %s: no program", j.Label)
	}
	if j.ThrottleInterval < 0 {
		return nil, fmt.Errorf("launchd job %s: negative throttle interval", j.Label)
	}
	if j.KeepAliveOnFailure && !j.RunAtLoad {
		return nil, fmt.Errorf("launchd job %s: failure-only keepalive requires run-at-load", j.Label)
	}
	if j.KeepAlive && j.KeepAliveOnFailure {
		return nil, fmt.Errorf("launchd job %s: conflicting keepalive policies", j.Label)
	}
	var buf bytes.Buffer
	buf.WriteString(plistHeader)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "\t")
	w := plistWriter{enc: enc}
	w.start("plist", xml.Attr{Name: xml.Name{Local: "version"}, Value: "1.0"})
	w.start("dict")
	w.key("Label")
	w.text("string", j.Label)
	w.key("ProgramArguments")
	w.start("array")
	for _, arg := range j.ProgramArguments {
		w.text("string", arg)
	}
	w.end()
	if j.RunAtLoad {
		w.key("RunAtLoad")
		w.empty("true")
	}
	if j.KeepAlive {
		w.key("KeepAlive")
		w.empty("true")
	} else if j.KeepAliveOnFailure {
		w.key("KeepAlive")
		w.start("dict")
		w.key("SuccessfulExit")
		w.empty("false")
		w.end()
	}
	if j.ThrottleInterval > 0 {
		w.key("ThrottleInterval")
		w.text("integer", fmt.Sprint(j.ThrottleInterval))
	}
	if j.EnableTransactions {
		w.key("EnableTransactions")
		w.empty("true")
	}
	if len(j.EnvironmentVariables) > 0 {
		w.key("EnvironmentVariables")
		w.start("dict")
		keys := slices.Sorted(func(yield func(string) bool) {
			for k := range j.EnvironmentVariables {
				if !yield(k) {
					return
				}
			}
		})
		for _, k := range keys {
			w.key(k)
			w.text("string", j.EnvironmentVariables[k])
		}
		w.end()
	}
	if s := j.SecureSocket; s != nil {
		w.key("Sockets")
		w.start("dict")
		w.key(s.Name)
		w.start("dict")
		w.key("SecureSocketWithKey")
		w.text("string", s.Key)
		w.end()
		w.end()
	}
	w.end() // dict
	w.end() // plist
	if w.err != nil {
		return nil, w.err
	}
	if err := enc.Flush(); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	// encoding/xml emits paired tags, but launchd's XPC plist parser requires
	// self-closing booleans. String contents are XML-escaped, so they cannot
	// match these replacements.
	data := bytes.ReplaceAll(buf.Bytes(), []byte("<true></true>"), []byte("<true/>"))
	data = bytes.ReplaceAll(data, []byte("<false></false>"), []byte("<false/>"))
	return data, nil
}

// plistWriter emits tokens and keeps the first error.
type plistWriter struct {
	enc   *xml.Encoder
	stack []string
	err   error
}

func (w *plistWriter) token(t xml.Token) {
	if w.err == nil {
		w.err = w.enc.EncodeToken(t)
	}
}

func (w *plistWriter) start(name string, attrs ...xml.Attr) {
	w.stack = append(w.stack, name)
	w.token(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
}

func (w *plistWriter) end() {
	name := w.stack[len(w.stack)-1]
	w.stack = w.stack[:len(w.stack)-1]
	w.token(xml.EndElement{Name: xml.Name{Local: name}})
}

func (w *plistWriter) text(name, value string) {
	w.start(name)
	w.token(xml.CharData(value))
	w.end()
}

func (w *plistWriter) empty(name string) {
	w.start(name)
	w.end()
}

func (w *plistWriter) key(name string) {
	w.text("key", name)
}
