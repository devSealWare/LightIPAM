package app

import (
	"bytes"
	"encoding/csv"
	"net/netip"
	"testing"
)

// testContext builds an importContext with one existing /24 subnet (with a
// "default" site) and one existing device, for the validator tests.
func testContext() importContext {
	p := netip.MustParsePrefix("192.168.10.0/24")
	return importContext{
		subnets:      []existingSubnet{{prefix: p, cidr: "192.168.10.0/24"}},
		subnetByCIDR: map[string]string{"192.168.10.0/24": "sub-1"},
		addresses:    map[string]bool{"192.168.10.5": true},
		sitesByName:  map[string]string{"default": "default"},
		devicesByName: map[string][]string{
			"nas":  {"dev-1"},
			"dupe": {"dev-2", "dev-3"},
		},
	}
}

func TestValidateSubnets(t *testing.T) {
	header := []string{"name", "cidr", "vlan", "site", "description"}
	records := [][]string{
		{"Existing", "192.168.10.0/24", "20", "Default", "updates by cidr"}, // update (exact match)
		{"New", "10.0.0.0/24", "30", "", "fresh"},                           // create
		{"Overlap", "192.168.10.128/25", "", "", ""},                        // error: overlaps existing
		{"Bad CIDR", "999.0.0.0/8", "", "", ""},                             // error: invalid
		{"Bad VLAN", "10.1.0.0/24", "9999", "", ""},                         // error: vlan range
		{"", "10.2.0.0/24", "", "", ""},                                     // error: name required
		{"Unknown site", "10.3.0.0/24", "", "Branch", ""},                   // error: unknown site
	}
	res, imports := validateSubnets(records, header, testContext())
	if res.FileError != "" {
		t.Fatalf("unexpected file error: %s", res.FileError)
	}
	if res.Created != 1 || res.Updated != 1 || res.Errors != 5 {
		t.Fatalf("got created=%d updated=%d errors=%d, want 1/1/5", res.Created, res.Updated, res.Errors)
	}
	if len(imports) != 2 {
		t.Fatalf("want 2 importable rows, got %d", len(imports))
	}
}

func TestValidateSubnetsInFileDuplicateAndOverlap(t *testing.T) {
	header := []string{"name", "cidr"}
	records := [][]string{
		{"A", "10.0.0.0/24"},
		{"B", "10.0.0.0/24"}, // duplicate cidr
		{"C", "10.0.0.0/16"}, // overlaps A within the file
	}
	res, _ := validateSubnets(records, header, testContext())
	if res.Created != 1 || res.Errors != 2 {
		t.Fatalf("got created=%d errors=%d, want 1/2", res.Created, res.Errors)
	}
}

func TestValidateSubnetsMissingColumn(t *testing.T) {
	res, imports := validateSubnets([][]string{{"x"}}, []string{"name"}, testContext())
	if res.FileError == "" {
		t.Fatal("want file error for missing cidr column")
	}
	if imports != nil {
		t.Fatal("want nil imports on file error")
	}
}

func TestValidateAddresses(t *testing.T) {
	header := []string{"address", "subnet", "state", "hostname", "device", "notes"}
	records := [][]string{
		{"192.168.10.5", "192.168.10.0/24", "assigned", "nas-1", "NAS", "update"}, // update (existing addr)
		{"192.168.10.20", "192.168.10.0/24", "reserved", "", "", "new"},           // create
		{"192.168.99.9", "", "assigned", "", "", ""},                              // error: no containing subnet
		{"192.168.10.21", "", "bogus", "", "", ""},                                // error: bad state
		{"nope", "", "assigned", "", "", ""},                                      // error: bad ip
		{"192.168.10.22", "", "assigned", "", "Dupe", ""},                         // error: ambiguous device
		{"192.168.10.23", "", "assigned", "", "Ghost", ""},                        // error: unknown device
	}
	res, imports := validateAddresses(records, header, testContext())
	if res.Created != 1 || res.Updated != 1 || res.Errors != 5 {
		t.Fatalf("got created=%d updated=%d errors=%d, want 1/1/5", res.Created, res.Updated, res.Errors)
	}
	for _, imp := range imports {
		if imp.SubnetID != "sub-1" {
			t.Fatalf("address %s located subnet %q, want sub-1", imp.Address, imp.SubnetID)
		}
	}
}

func TestValidateAddressesDeviceLink(t *testing.T) {
	header := []string{"address", "state", "device"}
	records := [][]string{{"192.168.10.30", "assigned", "NAS"}}
	_, imports := validateAddresses(records, header, testContext())
	if len(imports) != 1 || imports[0].DeviceID != "dev-1" {
		t.Fatalf("want device dev-1 linked, got %+v", imports)
	}
}

func TestValidateDevices(t *testing.T) {
	header := []string{"name", "description"}
	records := [][]string{
		{"NAS", "exists -> update"}, // update (existing)
		{"Switch", "new"},           // create
		{"Switch", "again"},         // update (seen earlier in file)
		{"", "no name"},             // error
	}
	res, imports := validateDevices(records, header, testContext())
	if res.Created != 1 || res.Updated != 2 || res.Errors != 1 {
		t.Fatalf("got created=%d updated=%d errors=%d, want 1/2/1", res.Created, res.Updated, res.Errors)
	}
	if len(imports) != 3 {
		t.Fatalf("want 3 importable device rows, got %d", len(imports))
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	cases := map[string]string{
		"=SUM(1+1)":      "'=SUM(1+1)",
		"@cmd|'/c calc'": "'@cmd|'/c calc'",
		"+1234":          "'+1234",
		"-1234":          "'-1234",
		"\ttabbed":       "'\ttabbed",
		"\rcr":           "'\rcr",
		"Normal name":    "Normal name",
		"":               "",
	}
	for in, want := range cases {
		if got := sanitizeCSVCell(in); got != want {
			t.Errorf("sanitizeCSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCSVExportNeutralizesFormulaInjection is the regression test for
// docs/agent/findings/0001-csv-formula-injection.md: a subnet named
// "=SUM(1+1)" must not reach the exported file as a live formula.
func TestCSVExportNeutralizesFormulaInjection(t *testing.T) {
	var buf bytes.Buffer
	cw := &csvCellWriter{csv.NewWriter(&buf)}
	_ = cw.Write([]string{"name", "cidr"})
	_ = cw.Write([]string{"=SUM(1+1)", "10.0.0.0/24"})
	cw.Flush()

	r := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse exported csv: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 rows, got %d", len(records))
	}
	if got := records[1][0]; got != "'=SUM(1+1)" {
		t.Fatalf("exported cell = %q, want a leading-quote-neutralized formula", got)
	}
}

func TestParseCSVStripsBOMAndHeader(t *testing.T) {
	body := "\ufeffName,CIDR\nOffice,192.168.10.0/24\n"
	header, records, err := parseCSV(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(header) != 2 || header[0] != "name" || header[1] != "cidr" {
		t.Fatalf("header not normalized/stripped: %#v", header)
	}
	if len(records) != 1 || records[0][1] != "192.168.10.0/24" {
		t.Fatalf("records wrong: %#v", records)
	}
}
