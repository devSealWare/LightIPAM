package ui

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/devSealWare/LightIPAM/internal/store"
)

//go:embed templates/*.html static/*.css
var assets embed.FS

type PageData struct {
	Title          string
	Error          string
	CSRF           string
	User           store.User
	Stats          store.DashboardStats
	Sites          []store.Site
	Subnets        []store.Subnet
	Subnet         store.Subnet
	Addresses      []store.IPAddress
	AddressStates  []string
	Devices        []store.Device
	Device         store.Device
	MACAddresses   []store.MACAddress
	AuditLogs      []store.AuditLog
	AuditActions   []string
	AuditSubjects  []string
	AuditActors    []store.User
	Form           map[string]string
	ActiveNav      string
	SuccessMessage string
}

func Render(w http.ResponseWriter, name string, data PageData) error {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"eq": func(a, b any) bool {
			return a == b
		},
	}).ParseFS(assets, "templates/base.html", "templates/"+name)
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
