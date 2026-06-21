// Command lightipam-cli is a thin client for the Light IPAM machine API (ADR
// 0024). It authenticates with a personal API token (minted on the account page)
// and manages subnets, addresses, and devices over the JSON API at /api/v1.
//
// Configuration comes from flags or the environment:
//
//	LIGHTIPAM_URL    base URL, e.g. https://ipam.example.com  (flag: --url)
//	LIGHTIPAM_TOKEN  a personal API token                     (flag: --token)
//	                 skip TLS verification (dev certs only)    (flag: --insecure)
//
// Global flags come before the command, e.g.:
//
//	lightipam-cli --url https://ipam.local:8080 whoami
//	lightipam-cli subnets create --cidr 10.0.0.0/24 --name "Core"
//	lightipam-cli subnets list
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	global := flag.NewFlagSet("lightipam-cli", flag.ContinueOnError)
	url := global.String("url", os.Getenv("LIGHTIPAM_URL"), "Light IPAM base URL (or LIGHTIPAM_URL)")
	token := global.String("token", os.Getenv("LIGHTIPAM_TOKEN"), "API token (or LIGHTIPAM_TOKEN)")
	insecure := global.Bool("insecure", os.Getenv("LIGHTIPAM_INSECURE") == "1", "skip TLS certificate verification (dev only)")
	global.Usage = usage
	if err := global.Parse(argv); err != nil {
		return err
	}
	args := global.Args()
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		return nil
	}
	if strings.TrimSpace(*url) == "" {
		return fmt.Errorf("set --url or LIGHTIPAM_URL")
	}
	c := &client{
		baseURL: strings.TrimRight(*url, "/"),
		token:   strings.TrimSpace(*token),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}},
		},
	}

	switch args[0] {
	case "whoami":
		return c.show("GET", "/api/v1/whoami", nil)
	case "subnets":
		return c.resource(args[1:], "subnets", []string{"cidr", "name", "site_id", "description"}, []string{"vlan"})
	case "addresses":
		return c.addresses(args[1:])
	case "devices":
		return c.resource(args[1:], "devices", []string{"name", "description"}, nil)
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type client struct {
	baseURL string
	token   string
	http    *http.Client
}

// do performs a request and returns the status and body, surfacing the API's JSON
// error message on a non-2xx response.
func (c *client) do(method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, out, nil
}

// show runs a request and prints the response, returning an error on a non-2xx.
func (c *client) show(method, path string, body any) error {
	status, out, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, status, apiErrorMessage(out))
	}
	printJSON(out)
	return nil
}

// resource handles the standard list/get/create/update/delete verbs for a
// top-level resource collection. strFields/intFields name the create/update body
// flags (string and integer typed, respectively).
func (c *client) resource(args []string, name string, strFields, intFields []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s <list|get|create|update|delete> ...", name)
	}
	base := "/api/v1/" + name
	switch args[0] {
	case "list":
		return c.show("GET", base, nil)
	case "get":
		id, err := needID(args, name)
		if err != nil {
			return err
		}
		return c.show("GET", base+"/"+id, nil)
	case "delete":
		id, err := needID(args, name)
		if err != nil {
			return err
		}
		return c.show("DELETE", base+"/"+id, nil)
	case "create":
		body, err := parseFields(name+" create", args[1:], strFields, intFields)
		if err != nil {
			return err
		}
		return c.show("POST", base, body)
	case "update":
		id, err := needID(args, name)
		if err != nil {
			return err
		}
		body, err := parseFields(name+" update", args[2:], strFields, intFields)
		if err != nil {
			return err
		}
		return c.show("PUT", base+"/"+id, body)
	default:
		return fmt.Errorf("unknown %s subcommand %q", name, args[0])
	}
}

// addresses handles the nested-under-subnet collection for list/create plus the
// flat get/update/delete by address id.
func (c *client) addresses(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: addresses <list|get|create|update|delete> ...")
	}
	strFields := []string{"address", "state", "hostname", "device_id", "notes"}
	switch args[0] {
	case "list":
		if len(args) < 2 {
			return fmt.Errorf("usage: addresses list <subnet-id>")
		}
		return c.show("GET", "/api/v1/subnets/"+args[1]+"/addresses", nil)
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: addresses create <subnet-id> --address <ip> [flags]")
		}
		body, err := parseFields("addresses create", args[2:], strFields, nil)
		if err != nil {
			return err
		}
		return c.show("POST", "/api/v1/subnets/"+args[1]+"/addresses", body)
	case "get":
		if len(args) < 2 {
			return fmt.Errorf("usage: addresses get <id>")
		}
		return c.show("GET", "/api/v1/addresses/"+args[1], nil)
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: addresses delete <id>")
		}
		return c.show("DELETE", "/api/v1/addresses/"+args[1], nil)
	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: addresses update <id> [flags]")
		}
		body, err := parseFields("addresses update", args[2:], strFields, nil)
		if err != nil {
			return err
		}
		return c.show("PUT", "/api/v1/addresses/"+args[1], body)
	default:
		return fmt.Errorf("unknown addresses subcommand %q", args[0])
	}
}

// parseFields builds a JSON request body from --field flags, including only the
// flags the user actually set (so an update is a partial change). Integer fields
// are emitted as JSON numbers.
func parseFields(label string, args, strFields, intFields []string) (map[string]any, error) {
	fs := flag.NewFlagSet(label, flag.ContinueOnError)
	strVals := map[string]*string{}
	for _, f := range strFields {
		strVals[f] = fs.String(f, "", "")
	}
	intVals := map[string]*int{}
	for _, f := range intFields {
		intVals[f] = fs.Int(f, 0, "")
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	body := map[string]any{}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, v := range strVals {
		if set[name] {
			body[name] = *v
		}
	}
	for name, v := range intVals {
		if set[name] {
			body[name] = *v
		}
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%s: provide at least one field flag (e.g. --%s)", label, firstOr(append(strFields, intFields...), "name"))
	}
	return body, nil
}

func needID(args []string, name string) (string, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return "", fmt.Errorf("usage: %s %s <id>", name, args[0])
	}
	return args[1], nil
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

func apiErrorMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(body))
}

func printJSON(body []byte) {
	if len(bytes.TrimSpace(body)) == 0 {
		return
	}
	var buf bytes.Buffer
	if json.Indent(&buf, body, "", "  ") == nil {
		fmt.Println(buf.String())
		return
	}
	fmt.Println(string(body))
}

func usage() {
	fmt.Fprint(os.Stderr, `lightipam-cli — Light IPAM machine API client

Usage:
  lightipam-cli [--url URL] [--token TOKEN] [--insecure] <command> ...

Commands:
  whoami
  subnets    list | get <id> | create --cidr <c> --name <n> [--vlan <v>] [--site-id <s>] [--description <d>]
             update <id> [flags] | delete <id>
  addresses  list <subnet-id> | get <id> | delete <id>
             create <subnet-id> --address <ip> [--state <s>] [--hostname <h>] [--device-id <id>] [--notes <n>]
             update <id> [flags]
  devices    list | get <id> | create --name <n> [--description <d>] | update <id> [flags] | delete <id>

Environment: LIGHTIPAM_URL, LIGHTIPAM_TOKEN, LIGHTIPAM_INSECURE=1
`)
}
