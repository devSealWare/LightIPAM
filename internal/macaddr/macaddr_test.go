package macaddr

import "testing"

func TestAnalyzePrivateRotatingMAC(t *testing.T) {
	analysis, err := Analyze("da:a1:19:22:33:44")
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.IsPrivate {
		t.Fatal("expected locally administered unicast MAC to be private")
	}
	if analysis.Vendor != "" {
		t.Fatalf("expected no vendor for private MAC, got %q", analysis.Vendor)
	}
}

func TestAnalyzeVendor(t *testing.T) {
	analysis, err := Analyze("b8:27:eb:00:11:22")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.IsPrivate {
		t.Fatal("expected globally administered MAC")
	}
	if analysis.Vendor != "Raspberry Pi" {
		t.Fatalf("unexpected vendor %q", analysis.Vendor)
	}
}
