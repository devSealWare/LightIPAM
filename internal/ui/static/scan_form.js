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
 */
(function () {
  "use strict";

  // Scan types that ignore the depth mode, so the picker is hidden for them.
  var NO_MODE = {
    arp_table: true,
    snmp_inventory: true,
    combined: true
  };

  var HINTS = {
    host_discovery: "Ping/ARP sweep to find live hosts. Mode sets scan depth.",
    service_detection: "Probes open TCP ports for running services. Mode sets port breadth and version depth.",
    os_probe: "Fingerprints the operating system. Mode sets depth.",
    combined: "Full deep nmap (all ports) + SNMP ARP harvest + SNMP inventory, merged into one picture. Unreachable SNMP is skipped, not failed.",
    arp_table: "Asks gateway/L3 devices for their ARP cache over SNMP to recover IP↔MAC bindings across subnets. Targets are the gateway IPs.",
    snmp_inventory: "Asks SNMP devices about themselves — name, OS, and the MACs of their own interfaces. Targets are the device IPs."
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

    function update() {
      var type = select.value;
      if (modeField) {
        modeField.style.display = NO_MODE[type] ? "none" : "";
      }
      if (hint) {
        hint.textContent = HINTS[type] || "";
      }
    }

    select.addEventListener("change", update);
    update();
  });
})();
