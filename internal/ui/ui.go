package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/devSealWare/LightIPAM/internal/backup"
	"github.com/devSealWare/LightIPAM/internal/scanner"
	"github.com/devSealWare/LightIPAM/internal/store"
)

//go:embed templates/*.html static
var assets embed.FS

type PageData struct {
	Title         string
	Error         string
	CSRF          string
	User          store.User
	Stats         store.DashboardStats
	Sites         []store.Site
	Subnets       []store.Subnet
	Subnet        store.Subnet
	Addresses     []store.IPAddress
	Address       store.IPAddress
	AddressStates []string
	Devices       []store.Device
	DeviceGroups  []store.DeviceGroup
	Device        store.Device
	MACAddresses  []store.MACAddress
	// Same-physical-device links (ADR 0029): confirmed hardware-group siblings
	// of the viewed device, and unconfirmed suggestions awaiting operator review.
	LinkedDevices   []store.LinkedDevice
	LinkSuggestions []store.DeviceLinkSuggestion
	AuditLogs       []store.AuditLog
	AuditActions    []string
	AuditSubjects   []string
	AuditActors     []store.User
	ScanAgents      []store.ScanAgent
	ScanAgent       store.ScanAgent
	// AgentDiagnostics, when set, renders the agent's network self-view (source/
	// route/interface, pin mode, nmap version, capabilities, warnings) on the
	// agent detail page after "Run diagnostics" (ADR 0027 §3).
	AgentDiagnostics  *scanner.AgentDiagnostics
	ScanJobs          []store.ScanJob
	ScanJob           store.ScanJob
	ScanObservations  []scanner.Observation
	ScanErrors        []scanner.ScanError
	ScanNotices       []scanner.ScanError
	ScanSchedules     []store.ScanSchedule
	ScanSchedule      store.ScanSchedule
	ScanTypes         []string
	ScanTypeGroups    []ScanTypeGroup
	ScanModes         []string
	AgentStatuses     []string
	DispatchReady     bool
	Discoveries       []store.Discovery
	Discovery         store.Discovery
	PendingDiscovery  int
	ConflictDiscovery int

	// DiscoveryPrompt, when set, opens the "create the missing subnet" modal on
	// the Discoveries page with a CIDR pre-filled from the scan. ImportableCount is
	// the number of pending, non-conflicting discoveries the "Import all" button
	// acts on (it is hidden when zero).
	DiscoveryPrompt  *DiscoverySubnetPrompt
	ImportableCount  int
	SearchQuery      string
	SearchResults    store.SearchResults
	Sessions         []store.Session
	CurrentSessionID string
	Users            []store.User

	// MFA / account
	MFAEnabled          bool
	TOTPSecretFormatted string
	TOTPURI             string
	RecoveryCodes       []string
	RecoveryRemaining   int

	// OIDCEnabled shows the "Sign in with SSO" control on the login page.
	OIDCEnabled bool

	// API tokens (account page, ADR 0024). APITokens lists the user's tokens;
	// NewAPIToken carries a just-created token's plaintext, shown exactly once.
	APITokens   []store.APIToken
	NewAPIToken string

	// Backup (settings tab)
	Backups        []backup.Backup
	BackupDir      string
	BackupEnabled  bool
	BackupWritable bool

	// Certificates (settings tab)
	CAReady         bool
	CAFingerprint   string
	CAExpiry        time.Time
	LeafDefaultDays int

	// Custom fields. CustomFields carries an entity's fields + values for the
	// entity forms and detail pages; CustomFieldDefs lists every definition for
	// the Settings management tab.
	CustomFields    []store.CustomFieldValue
	CustomFieldDefs []store.CustomFieldDef

	// Policy / health. PolicyGroups carries the grouped findings for the /policy
	// page; PolicySummary the severity counts for that page's header and the
	// dashboard widget.
	PolicyGroups  []store.PolicyFindingGroup
	PolicySummary store.PolicySummary

	// Notifications (change webhooks, settings tab). Webhooks lists the registered
	// endpoints; WebhookDeliveries the recent delivery log; WebhookCategories the
	// subscribable event categories for the form checkboxes.
	Webhooks          []store.Webhook
	WebhookDeliveries []store.WebhookDelivery
	WebhookCategories []string

	Form           map[string]string
	ActiveNav      string
	ActiveTab      string
	SuccessMessage string
	ImportResult   store.ImportResult
}

// ScanTypeGroup is a labeled set of scan types rendered as an <optgroup> in the
// scan/schedule forms, so the recommended Combined scan leads and the granular
// single-source scans are clearly secondary.
type ScanTypeGroup struct {
	Label string
	Types []string
}

// DiscoverySubnetPrompt drives the "create the missing subnet" modal on the
// Discoveries page. It is set when importing a discovery (single or via "Import
// all") needs a subnet that does not exist yet: the form is pre-filled with a
// suggested CIDR and the discovered VLAN, and on save it creates the subnet then
// resumes the import. Flow is "import-one" (after saving, import DiscoveryID) or
// "import-all" (after saving, re-check for more missing subnets, then import
// everything). TargetIP is the discovered host the new subnet must contain, used
// both to validate the operator-edited CIDR and in the explanatory copy.
type DiscoverySubnetPrompt struct {
	Flow        string
	DiscoveryID string
	TargetIP    string
	Heading     string
	Context     string
	// Error is a validation/creation failure shown inside the modal so the operator
	// fixes it in place (e.g. an overlapping or non-containing CIDR).
	Error string
	// Remaining counts how many distinct missing subnets still need defining
	// (import-all only); the modal shows it so the operator knows how many prompts
	// are left. Zero for the single-import flow.
	Remaining int
	Form      map[string]string
	Sites     []store.Site
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
		"contains": func(values []string, target string) bool {
			for _, v := range values {
				if v == target {
					return true
				}
			}
			return false
		},
		"split": func(value, sep string) []string {
			if value == "" {
				return nil
			}
			return strings.Split(value, sep)
		},
		"optionLabel":     optionLabel,
		"entityTypeLabel": entityTypeLabel,
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
		"filesize": func(size int64) string {
			const unit = 1024
			if size < unit {
				return fmt.Sprintf("%d B", size)
			}
			div, exp := int64(unit), 0
			for n := size / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
		},
	}).ParseFS(assets, "templates/base.html", "templates/shell.html", "templates/"+name)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return tmpl.ExecuteTemplate(w, "base.html", data)
}

// optionLabel renders a scan-type or scan-mode enum value as a friendly label
// for a <select>. The option's value attribute keeps the raw enum, so the posted
// form is unchanged; only the displayed text is humanized. Unknown values fall
// back to the raw string.
func optionLabel(value string) string {
	switch value {
	case "light_active":
		return "Light — top 1000 ports"
	case "standard_active":
		return "Standard — top 1000 + full version probes + OS"
	case "deep_active":
		return "Deep — all ports, fast service detection + OS"
	case "host_discovery":
		return "Host discovery"
	case "service_detection":
		return "Service detection"
	case "os_probe":
		return "OS probe"
	case "combined":
		return "Combined — every source, merged (recommended)"
	case "arp_table":
		return "ARP table (SNMP)"
	case "snmp_inventory":
		return "SNMP inventory"
	case "name_lookup":
		return "Names (NetBIOS + mDNS)"
	case "dns_lookup":
		return "DNS names (reverse + forward)"
	case "dhcp_leases":
		return "DHCP leases (file)"
	case "lldp_cdp":
		return "LLDP/CDP neighbors (SNMP)"
	default:
		return value
	}
}

// entityTypeLabel renders a custom-field entity type as a friendly singular
// noun for the management UI. Unknown values fall back to the raw string.
func entityTypeLabel(entityType string) string {
	switch entityType {
	case store.CustomFieldSubnet:
		return "Subnet"
	case store.CustomFieldAddress:
		return "Address"
	case store.CustomFieldDevice:
		return "Device"
	default:
		return entityType
	}
}

func StaticCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	http.ServeFileFS(w, r, assets, "static/app.css")
}

func StaticHandler() http.Handler {
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServerFS(staticFS)
}

func Favicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	http.ServeFileFS(w, r, assets, "static/favicon.ico")
}

func AppleTouchIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	http.ServeFileFS(w, r, assets, "static/apple-touch-icon.png")
}

func SiteManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	http.ServeFileFS(w, r, assets, "static/site.webmanifest")
}

func StaticJS(w http.ResponseWriter, r *http.Request) {
	serveJS(w, r, "static/columns.js")
}

// ScanFormJS serves the progressive-enhancement script for the scan/schedule
// forms: it shows the mode picker only for nmap scan types and updates the
// per-type hint. The forms work without it (the server normalizes the mode).
func ScanFormJS(w http.ResponseWriter, r *http.Request) {
	serveJS(w, r, "static/scan_form.js")
}

// BulkJS serves the progressive-enhancement script for the bulk-edit tables:
// select-all, a live selection count, and showing only the action's contextual
// field. The tables work without it (checkboxes + an always-visible action bar).
func BulkJS(w http.ResponseWriter, r *http.Request) {
	serveJS(w, r, "static/bulk.js")
}

func serveJS(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	http.ServeFileFS(w, r, assets, name)
}
