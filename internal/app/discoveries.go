package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/devSealWare/LightIPAM/internal/ipam"
	"github.com/devSealWare/LightIPAM/internal/store"
	"github.com/devSealWare/LightIPAM/internal/ui"
)

func (a *App) discoveriesIndex(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	var prompt *ui.DiscoverySubnetPrompt
	successMsg := ""
	errMsg := r.URL.Query().Get("error")

	if n := r.URL.Query().Get("imported"); n != "" {
		if count, err := strconv.Atoi(n); err == nil && count > 0 {
			if count == 1 {
				successMsg = "Imported 1 discovered host into IPAM."
			} else {
				successMsg = fmt.Sprintf("Imported %d discovered hosts into IPAM.", count)
			}
		}
	}

	// A query flag opens the "create the missing subnet" modal: resolve_one targets
	// a single discovery the operator clicked Import on; resolve=1 walks the subnets
	// the "Import all" flow still needs. Both pre-fill a CIDR from the scan.
	if id := r.URL.Query().Get("resolve_one"); id != "" {
		p, err := a.resolveOnePrompt(r, id)
		if err != nil {
			// The discovery vanished (or already has a subnet) — fall back to the queue.
			http.Redirect(w, r, "/discoveries", http.StatusSeeOther)
			return
		}
		prompt = p
	} else if r.URL.Query().Get("resolve") == "1" {
		p, err := a.resolveAllPrompt(r)
		if err != nil {
			a.logger.Error("resolve subnets", "error", err)
		} else {
			prompt = p // nil when nothing is missing
		}
	}

	a.renderDiscoveries(w, r, session, prompt, errMsg, successMsg)
}

// renderDiscoveries draws the queue, the filter chips, the "Import all" control,
// and — when prompt is non-nil — the subnet-creation modal. It is the single
// render path so the import and subnet-create handlers can re-render with an
// in-context error without duplicating the page assembly.
func (a *App) renderDiscoveries(w http.ResponseWriter, r *http.Request, session store.Session, prompt *ui.DiscoverySubnetPrompt, errMsg, successMsg string) {
	status := r.URL.Query().Get("status")
	reconcile := r.URL.Query().Get("reconcile")
	discoveries, err := a.store.ListDiscoveries(r.Context(), status, reconcile, 200)
	if err != nil {
		a.logger.Error("list discoveries", "error", err)
		http.Error(w, "Unable to load discoveries", http.StatusInternalServerError)
		return
	}
	pending, err := a.store.CountPendingDiscoveries(r.Context())
	if err != nil {
		a.logger.Error("count pending discoveries", "error", err)
	}
	conflicts, err := a.store.CountUnreviewedConflicts(r.Context())
	if err != nil {
		a.logger.Error("count conflict discoveries", "error", err)
	}
	importable := 0
	if targets, err := a.store.ListPendingImportTargets(r.Context()); err != nil {
		a.logger.Error("list import targets", "error", err)
	} else {
		importable = len(targets)
	}
	if prompt != nil && prompt.Sites == nil {
		if sites, err := a.store.ListSites(r.Context()); err != nil {
			a.logger.Error("list sites", "error", err)
		} else {
			prompt.Sites = sites
		}
	}
	_ = ui.Render(w, "discoveries.html", ui.PageData{
		Title:             "Discoveries",
		User:              session.User,
		CSRF:              session.CSRFToken,
		Discoveries:       discoveries,
		PendingDiscovery:  pending,
		ConflictDiscovery: conflicts,
		ImportableCount:   importable,
		DiscoveryPrompt:   prompt,
		Error:             errMsg,
		SuccessMessage:    successMsg,
		Form:              map[string]string{"status": status, "reconcile": reconcile},
		ActiveNav:         "discoveries",
	})
}

func (a *App) discoveryImport(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("device_name"))
	discovery, err := a.store.ImportDiscovery(r.Context(), id, name)
	if err != nil {
		if errors.Is(err, store.ErrNoContainingSubnet) {
			// No managed subnet contains the host yet — open the subnet-creation modal
			// pre-filled from the scan instead of dead-ending on an error.
			http.Redirect(w, r, "/discoveries?resolve_one="+url.QueryEscape(id), http.StatusSeeOther)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("import discovery", "error", err)
		http.Error(w, "Unable to import discovery", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID)
	a.autoLinkBySerial(r, discovery.ImportedDeviceID)
	http.Redirect(w, r, "/discoveries?imported=1", http.StatusSeeOther)
}

// discoveriesImportAll imports every pending, non-conflicting discovery in one
// click. If any of them fall outside the managed subnets, it opens the
// subnet-creation modal (one subnet at a time) instead of importing — the modal
// loops back here until every host has a home, then the import runs.
func (a *App) discoveriesImportAll(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	targets, err := a.store.ListPendingImportTargets(r.Context())
	if err != nil {
		a.logger.Error("list import targets", "error", err)
		http.Error(w, "Unable to import discoveries", http.StatusInternalServerError)
		return
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/discoveries?error="+url.QueryEscape("There are no discoveries ready to import. Conflicts are reviewed one at a time."), http.StatusSeeOther)
		return
	}
	if len(missingSubnetGroups(targets)) > 0 {
		http.Redirect(w, r, "/discoveries?resolve=1", http.StatusSeeOther)
		return
	}
	count, err := a.importTargets(r, session, targets)
	if err != nil {
		a.logger.Error("import all discoveries", "error", err)
		http.Error(w, "Unable to import discoveries", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/discoveries?imported="+strconv.Itoa(count), http.StatusSeeOther)
}

// discoverySubnetCreate is the subnet-creation modal's submit handler. It creates
// the subnet (validating that it actually contains the host being imported), then
// resumes the flow that opened it: import-one imports the one discovery, while
// import-all re-checks for any remaining missing subnets and, once there are none,
// imports everything.
func (a *App) discoverySubnetCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	flow := r.FormValue("flow")
	if flow != "import-one" {
		flow = "import-all"
	}
	discoveryID := strings.TrimSpace(r.FormValue("discovery_id"))
	targetIP := strings.TrimSpace(r.FormValue("target_ip"))

	input, form, err := subnetInputFromRequest(r)
	if err != nil {
		a.renderSubnetPromptError(w, r, session, flow, discoveryID, targetIP, form, err.Error())
		return
	}
	// The operator may widen or narrow the suggested CIDR; make sure it still covers
	// the discovered host, otherwise the import that follows would not find it.
	if targetIP != "" {
		if contains, err := ipam.Contains(input.CIDR, targetIP); err == nil && !contains {
			a.renderSubnetPromptError(w, r, session, flow, discoveryID, targetIP, form,
				fmt.Sprintf("That subnet doesn’t contain %s — widen the range so it does.", targetIP))
			return
		}
	}

	subnet, err := a.store.CreateSubnet(r.Context(), input)
	if err != nil {
		a.renderSubnetPromptError(w, r, session, flow, discoveryID, targetIP, form, subnetError(err))
		return
	}
	a.saveCustomFieldValues(r, store.CustomFieldSubnet, subnet.ID)
	a.audit(r, &session.User.ID, "subnet.created", "subnet", subnet.ID)

	if flow == "import-one" {
		if discoveryID != "" {
			discovery, err := a.store.ImportDiscovery(r.Context(), discoveryID, "")
			if err != nil {
				if errors.Is(err, store.ErrNoContainingSubnet) {
					http.Redirect(w, r, "/discoveries?resolve_one="+url.QueryEscape(discoveryID), http.StatusSeeOther)
					return
				}
				a.logger.Error("import discovery", "error", err)
				http.Error(w, "Unable to import discovery", http.StatusInternalServerError)
				return
			}
			a.audit(r, &session.User.ID, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID)
			a.autoLinkBySerial(r, discovery.ImportedDeviceID)
		}
		http.Redirect(w, r, "/discoveries?imported=1", http.StatusSeeOther)
		return
	}

	// import-all: the new subnet may have covered several hosts, but others can still
	// be homeless — re-check and prompt for the next one, otherwise import everything.
	targets, err := a.store.ListPendingImportTargets(r.Context())
	if err != nil {
		a.logger.Error("list import targets", "error", err)
		http.Error(w, "Unable to import discoveries", http.StatusInternalServerError)
		return
	}
	if len(missingSubnetGroups(targets)) > 0 {
		http.Redirect(w, r, "/discoveries?resolve=1", http.StatusSeeOther)
		return
	}
	count, err := a.importTargets(r, session, targets)
	if err != nil {
		a.logger.Error("import all discoveries", "error", err)
		http.Error(w, "Unable to import discoveries", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/discoveries?imported="+strconv.Itoa(count), http.StatusSeeOther)
}

// importTargets imports each discovery that already has a containing subnet,
// auditing one event per imported address. A target that lost its subnet to a
// concurrent delete is skipped rather than failing the whole batch.
func (a *App) importTargets(r *http.Request, session store.Session, targets []store.DiscoveryImportTarget) (int, error) {
	count := 0
	for _, t := range targets {
		if !t.HasSubnet {
			continue
		}
		discovery, err := a.store.ImportDiscovery(r.Context(), t.ID, "")
		if err != nil {
			if errors.Is(err, store.ErrNoContainingSubnet) {
				continue
			}
			return count, err
		}
		a.audit(r, &session.User.ID, "scan.discovery.imported", "ip_address", discovery.ImportedAddressID)
		a.autoLinkBySerial(r, discovery.ImportedDeviceID)
		count++
	}
	return count, nil
}

// renderSubnetPromptError re-opens the subnet-creation modal with the operator's
// edits preserved and the failure shown in context.
func (a *App) renderSubnetPromptError(w http.ResponseWriter, r *http.Request, session store.Session, flow, discoveryID, targetIP string, form map[string]string, errMsg string) {
	remaining := 0
	if flow == "import-all" {
		if targets, err := a.store.ListPendingImportTargets(r.Context()); err == nil {
			remaining = len(missingSubnetGroups(targets))
		}
		if remaining == 0 {
			remaining = 1 // the subnet wasn't created, so at least this one still remains
		}
	}
	prompt := subnetPrompt(flow, discoveryID, targetIP, remaining, form)
	prompt.Error = errMsg
	a.renderDiscoveries(w, r, session, prompt, "", "")
}

// resolveOnePrompt builds the modal for importing a single discovery whose
// address has no managed subnet.
func (a *App) resolveOnePrompt(r *http.Request, id string) (*ui.DiscoverySubnetPrompt, error) {
	discovery, err := a.store.GetDiscovery(r.Context(), id)
	if err != nil {
		return nil, err
	}
	cidr, err := suggestSubnetCIDR(discovery.IP, a.discoveryScanTargets(r, discovery.JobID))
	if err != nil {
		return nil, err
	}
	return subnetPrompt("import-one", discovery.ID, discovery.IP, 0, subnetPromptForm(cidr, discovery.VLAN)), nil
}

// discoveryScanTargets returns the targets of the scan job that observed a
// discovery, so the subnet suggestion can match the exact network the operator
// scanned. A missing or no-longer-present job yields nil, and the suggestion falls
// back to the /24 heuristic.
func (a *App) discoveryScanTargets(r *http.Request, jobID string) []string {
	if jobID == "" {
		return nil
	}
	job, err := a.store.GetScanJob(r.Context(), jobID)
	if err != nil {
		return nil
	}
	return job.Targets
}

// resolveAllPrompt builds the modal for the next subnet the "Import all" flow
// still needs, or returns nil when every host already has one.
func (a *App) resolveAllPrompt(r *http.Request) (*ui.DiscoverySubnetPrompt, error) {
	targets, err := a.store.ListPendingImportTargets(r.Context())
	if err != nil {
		return nil, err
	}
	missing := missingSubnetGroups(targets)
	if len(missing) == 0 {
		return nil, nil
	}
	g := missing[0]
	return subnetPrompt("import-all", "", g.RepIP, len(missing), subnetPromptForm(g.CIDR, g.VLAN)), nil
}

// subnetPrompt assembles the view model for the subnet-creation modal, with copy
// tailored to whether it was opened for a single import or the "Import all" loop.
func subnetPrompt(flow, discoveryID, targetIP string, remaining int, form map[string]string) *ui.DiscoverySubnetPrompt {
	p := &ui.DiscoverySubnetPrompt{
		Flow:        flow,
		DiscoveryID: discoveryID,
		TargetIP:    targetIP,
		Remaining:   remaining,
		Form:        form,
	}
	if flow == "import-one" {
		p.Heading = "Add the subnet for this host"
		p.Context = fmt.Sprintf("%s isn’t inside any managed subnet yet. The network and mask are filled in from the scan — name it and save, and the host imports automatically.", targetIP)
		return p
	}
	p.Heading = "Add a missing subnet"
	if remaining > 1 {
		p.Context = fmt.Sprintf("%s belongs to %s, which isn’t managed yet. %d subnets still need defining before everything can import.", targetIP, form["cidr"], remaining)
	} else {
		p.Context = fmt.Sprintf("%s belongs to %s, which isn’t managed yet. This is the last subnet to define — saving it imports every discovered host.", targetIP, form["cidr"])
	}
	return p
}

// subnetPromptForm seeds the modal's subnet form with the suggested CIDR, the
// default site, and the discovered VLAN when the scan learned one.
func subnetPromptForm(cidr string, vlan int) map[string]string {
	form := map[string]string{
		"cidr":        cidr,
		"site_id":     "default",
		"name":        "",
		"description": "",
	}
	if vlan > 0 {
		form["vlan"] = intString(vlan)
	}
	return form
}

// missingSubnet is one suggested network that one or more discovered hosts need but
// no managed subnet provides yet — the exact CIDR the operator scanned when known,
// otherwise the /24 containing the host. RepIP is a representative host (the lowest
// address) used to validate the operator-edited CIDR.
type missingSubnet struct {
	CIDR  string
	RepIP string
	VLAN  int
	Count int
}

// missingSubnetGroups collapses the targets that lack a containing subnet into one
// suggested network each (see suggestSubnetCIDR — the scanned CIDR when known), so a
// scan that turns up several hosts on the same network asks the operator to define it
// only once. Groups are returned in ascending network order for a stable, predictable
// prompt sequence.
func missingSubnetGroups(targets []store.DiscoveryImportTarget) []missingSubnet {
	groups := map[string]*missingSubnet{}
	for _, t := range targets {
		if t.HasSubnet {
			continue
		}
		cidr, err := suggestSubnetCIDR(t.IP, t.ScannedTargets)
		if err != nil {
			continue
		}
		g, ok := groups[cidr]
		if !ok {
			g = &missingSubnet{CIDR: cidr, RepIP: t.IP, VLAN: t.VLAN}
			groups[cidr] = g
		}
		g.Count++
		if g.VLAN == 0 && t.VLAN != 0 {
			g.VLAN = t.VLAN
		}
	}
	out := make([]missingSubnet, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, _ := netip.ParsePrefix(out[i].CIDR)
		aj, _ := netip.ParsePrefix(out[j].CIDR)
		return ai.Addr().Less(aj.Addr())
	})
	return out
}

// suggestSubnetCIDR proposes the subnet to pre-fill in the modal for a discovered
// host. When the scan that found the host targeted a network (a CIDR) that contains
// it, that exact network is suggested — it is provably what the operator scanned, so
// the prefill is correct rather than a guess (e.g. a scan of 192.168.0.0/28 suggests
// /28, not a blanket /24). The most specific containing target wins when several
// overlap. Only when no scanned network is known — the host was scanned as a single
// bare-IP target, which reveals no subnet boundary — does it fall back to the /24
// that contains the host, the common small-business default.
func suggestSubnetCIDR(ip string, scannedTargets []string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}
	if !addr.Is4() {
		return "", fmt.Errorf("only IPv4 hosts are supported")
	}
	if cidr, ok := containingTargetCIDR(addr, scannedTargets); ok {
		return cidr, nil
	}
	return netip.PrefixFrom(addr, 24).Masked().String(), nil
}

// containingTargetCIDR returns the most specific scanned CIDR target that contains
// addr, masked to its network address. Single-host targets (a bare IP, or a /32) are
// ignored — they name the host, not a network worth proposing as a subnet — and a
// malformed target is skipped rather than failing. Returns ok=false when no
// multi-host scanned network covers the address.
func containingTargetCIDR(addr netip.Addr, targets []string) (string, bool) {
	var best netip.Prefix
	for _, t := range targets {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(t))
		if err != nil {
			continue // a bare IP or malformed target: no network to adopt
		}
		if !prefix.Addr().Is4() || prefix.Bits() >= 32 {
			continue // a /32 is a single host, not a subnet
		}
		prefix = prefix.Masked()
		if !prefix.Contains(addr) {
			continue
		}
		if !best.IsValid() || prefix.Bits() > best.Bits() {
			best = prefix
		}
	}
	if !best.IsValid() {
		return "", false
	}
	return best.String(), true
}

func (a *App) discoveryDismiss(w http.ResponseWriter, r *http.Request) {
	session, ok := a.requireSession(w, r)
	if !ok {
		return
	}
	if !a.verifySessionCSRF(r, session) {
		http.Error(w, "Invalid form token", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := a.store.DismissDiscovery(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		a.logger.Error("dismiss discovery", "error", err)
		http.Error(w, "Unable to dismiss discovery", http.StatusInternalServerError)
		return
	}
	a.audit(r, &session.User.ID, "scan.discovery.dismissed", "scan_discovery", id)
	http.Redirect(w, r, "/discoveries", http.StatusSeeOther)
}

// autoLinkBySerial runs the opt-in gold-confidence auto-link (ADR 0030) after a
// manual discovery import: when the Settings → Discovery toggle is enabled and
// the imported device's chassis serial exactly matches other devices' (disjoint
// subnets, dismissed pairs respected), they are linked as one physical device
// and audited. Failures are logged, never fatal — the import already succeeded.
func (a *App) autoLinkBySerial(r *http.Request, deviceID string) {
	if deviceID == "" {
		return
	}
	linked, err := a.store.AutoLinkDeviceBySerial(r.Context(), deviceID)
	if err != nil {
		a.logger.Error("auto-link device by serial", "device", deviceID, "error", err)
		return
	}
	if len(linked) > 0 {
		a.audit(r, nil, "device.link.auto", "device", deviceID)
	}
}
