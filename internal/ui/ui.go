package ui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
)

//go:embed templates/*.html static/*.css static/*.js
var assets embed.FS

type PageData struct {
	Title             string
	Error             string
	CSRF              string
	User              store.User
	Stats             store.DashboardStats
	Sites             []store.Site
	Subnets           []store.Subnet
	Subnet            store.Subnet
	Addresses         []store.IPAddress
	Address           store.IPAddress
	AddressStates     []string
	Devices           []store.Device
	DeviceGroups      []store.DeviceGroup
	Device            store.Device
	MACAddresses      []store.MACAddress
	AuditLogs         []store.AuditLog
	AuditActions      []string
	AuditSubjects     []string
	AuditActors       []store.User
	ScanAgents        []store.ScanAgent
	ScanAgent         store.ScanAgent
	ScanJobs          []store.ScanJob
	ScanJob           store.ScanJob
	ScanObservations  []scanner.Observation
	ScanErrors        []scanner.ScanError
	ScanSchedules     []store.ScanSchedule
	ScanSchedule      store.ScanSchedule
	ScanTypes         []string
	ScanModes         []string
	AgentStatuses     []string
	DispatchReady     bool
	Discoveries       []store.Discovery
	Discovery         store.Discovery
	PendingDiscovery  int
	ConflictDiscovery int
	SearchQuery       string
	SearchResults     store.SearchResults
	Form              map[string]string
	ActiveNav         string
	SuccessMessage    string
}

func Render(w http.ResponseWriter, name string, data PageData) error {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"eq": func(a, b any) bool {
			return a == b
		},
		"ne": func(a, b any) bool {
			return a != b
		},
		"join": func(values []string, sep string) string {
			return strings.Join(values, sep)
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, fmt.Errorf("dict requires an even number of arguments")
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				m[key] = pairs[i+1]
			}
			return m, nil
		},
		"datetime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02 15:04")
		},
		"datetimeptr": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02 15:04")
		},
	}).ParseFS(assets, "templates/base.html", "templates/shell.html", "templates/"+name)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

func StaticCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	http.ServeFileFS(w, r, assets, "static/app.css")
}

func StaticJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeFileFS(w, r, assets, "static/columns.js")
}
