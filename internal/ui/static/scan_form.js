/* Light IPAM — scan form dynamic options.
 *
 * Progressive enhancement: the scan and schedule forms render every field
 * server-side, and the server normalizes the mode by scan type, so with JS
 * disabled the forms still submit a valid job. When enabled, this hides the
 * Mode picker for the scan types that have no depth (ARP, SNMP, and Combined)
 * and shows a short hint describing the selected scan.
 *
 * Markup contract (set in the templates):
 *   [data-scan-type]        the scan-type <select>
 *   [data-scan-mode-field]  the wrapper around the Mode picker, hidden when N/A
 *   [data-scan-hint]        an element whose text is set to the per-type hint
 *   [data-scan-timeout]     the timeout <input>; its placeholder shows the
 *                           per-type default used when left blank
 */
(function () {
  "use strict";

  // Scan types that ignore the depth mode, so the picker is hidden for them.
  var NO_MODE = {
    arp_table: true,
    snmp_inventory: true,
    name_lookup: true,
    dns_lookup: true,
    lldp_cdp: true,
    combined: true
  };

  // Per-host timeout defaults (seconds), mirroring app.defaultTimeoutForType.
  // Shown as the timeout field's placeholder when the operator leaves it blank.
  var TIMEOUTS = {
    host_discovery: 120,
    service_detection: 600,
    os_probe: 900,
    combined: 1200,
    arp_table: 180,
    snmp_inventory: 300,
    name_lookup: 120,
    dns_lookup: 120,
    lldp_cdp: 300
  };

  var HINTS = {
    host_discovery: "Ping/ARP sweep to find live hosts. Mode sets scan depth.",
    service_detection: "Probes open TCP ports for running services. Mode sets port breadth and version depth.",
    os_probe: "Fingerprints the operating system. Mode sets depth.",
    combined: "Full deep nmap (all ports) + SNMP ARP harvest + SNMP inventory + NetBIOS/mDNS names + DNS names + LLDP/CDP neighbors, merged into one picture. Unreachable enrichment is skipped, not failed.",
    arp_table: "Asks gateway/L3 devices for their ARP cache over SNMP to recover IP↔MAC bindings across subnets. Targets are the gateway IPs.",
    snmp_inventory: "Asks SNMP devices about themselves — name, OS, and the MACs of their own interfaces. Targets are the device IPs.",
    name_lookup: "Asks hosts for their name over NetBIOS (UDP/137) and mDNS (UDP/5353) — recovers names with no DNS record. Targets are the host IPs.",
    dns_lookup: "Resolves each host's name from your DNS (reverse PTR) and forward-confirms it. Targets are the host IPs.",
    lldp_cdp: "Asks switches/routers for their LLDP and CDP neighbor tables over SNMP — maps which devices are wired where. Targets are the switch/router IPs."
  };

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  ready(function () {
    var select = document.querySelector("[data-scan-type]");
    if (!select) {
      return;
    }
    var modeField = document.querySelector("[data-scan-mode-field]");
    var hint = document.querySelector("[data-scan-hint]");
    var timeout = document.querySelector("[data-scan-timeout]");

    function update() {
      var type = select.value;
      if (modeField) {
        modeField.style.display = NO_MODE[type] ? "none" : "";
      }
      if (hint) {
        hint.textContent = HINTS[type] || "";
      }
      if (timeout) {
        timeout.placeholder = TIMEOUTS[type] ? "auto (" + TIMEOUTS[type] + "s)" : "auto";
      }
    }

    select.addEventListener("change", update);
    update();
  });
})();
