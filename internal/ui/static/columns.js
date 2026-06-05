/* Light IPAM — selectable table columns (issue #34).
 *
 * Progressive enhancement: tables render fully server-side, so with JS
 * disabled every column stays visible. When enabled, this wires the per-table
 * "Columns" dropdown, persists the choice in localStorage, and shows/hides
 * columns by recomputing each grid row's template from the visible weights.
 *
 * Markup contract (set in the templates):
 *   [data-cols-table="<key>"]   wrapper that scopes one table's columns
 *   [data-cols-grid]            each grid row (header + data rows) to resize
 *   [data-col="<key>"]          a cell within a grid row
 *   [data-weight="<track>"]     grid track for that column (on header cells)
 *   [data-cols-toggle]          the "Columns" button (starts .hidden)
 *   [data-cols-menu]            the dropdown panel (starts .hidden)
 *   [data-col-toggle][value]    a checkbox; defaultChecked is the default
 */
(function () {
  "use strict";

  var PREFIX = "lightipam.cols.";

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  function setupTable(section) {
    var key = section.getAttribute("data-cols-table");
    if (!key) {
      return;
    }
    var storageKey = PREFIX + key;
    var grids = Array.prototype.slice.call(section.querySelectorAll("[data-cols-grid]"));
    if (!grids.length) {
      return;
    }

    // Derive column order + grid weights from the first grid carrying weights
    // (the header row); data rows only need the per-cell display toggle.
    var headerGrid = null;
    for (var i = 0; i < grids.length; i++) {
      if (grids[i].querySelector("[data-col][data-weight]")) {
        headerGrid = grids[i];
        break;
      }
    }
    if (!headerGrid) {
      headerGrid = grids[0];
    }

    var order = [];
    var weights = {};
    Array.prototype.forEach.call(headerGrid.querySelectorAll("[data-col]"), function (cell) {
      var col = cell.getAttribute("data-col");
      if (order.indexOf(col) === -1) {
        order.push(col);
        weights[col] = cell.getAttribute("data-weight") || "1fr";
      }
    });

    var toggles = Array.prototype.slice.call(section.querySelectorAll("[data-col-toggle]"));
    var toggleable = {};
    toggles.forEach(function (t) {
      toggleable[t.value] = true;
    });

    function defaults() {
      var vis = {};
      order.forEach(function (col) {
        if (!toggleable[col]) {
          vis[col] = true; // fixed column, always visible
        }
      });
      toggles.forEach(function (t) {
        vis[t.value] = t.defaultChecked;
      });
      return vis;
    }

    function load() {
      var vis = defaults();
      try {
        var raw = window.localStorage.getItem(storageKey);
        if (raw) {
          var saved = JSON.parse(raw);
          if (saved && typeof saved === "object") {
            toggles.forEach(function (t) {
              if (Object.prototype.hasOwnProperty.call(saved, t.value)) {
                vis[t.value] = !!saved[t.value];
              }
            });
          }
        }
      } catch (e) {
        /* corrupt or unavailable storage — fall back to defaults */
      }
      return vis;
    }

    function save(vis) {
      var out = {};
      toggles.forEach(function (t) {
        out[t.value] = !!vis[t.value];
      });
      try {
        window.localStorage.setItem(storageKey, JSON.stringify(out));
      } catch (e) {
        /* ignore quota / private-mode errors */
      }
    }

    function apply(vis) {
      var template = order
        .filter(function (c) {
          return vis[c];
        })
        .map(function (c) {
          return weights[c];
        })
        .join(" ");
      grids.forEach(function (grid) {
        grid.style.gridTemplateColumns = template;
        Array.prototype.forEach.call(grid.querySelectorAll("[data-col]"), function (cell) {
          cell.style.display = vis[cell.getAttribute("data-col")] ? "" : "none";
        });
      });
      toggles.forEach(function (t) {
        t.checked = !!vis[t.value];
      });
    }

    var visible = load();
    apply(visible);

    toggles.forEach(function (t) {
      t.addEventListener("change", function () {
        visible[t.value] = t.checked;
        save(visible);
        apply(visible);
      });
    });

    var toggleBtn = section.querySelector("[data-cols-toggle]");
    var menu = section.querySelector("[data-cols-menu]");
    if (toggleBtn) {
      toggleBtn.classList.remove("hidden");
    }
    if (toggleBtn && menu) {
      toggleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        var nowHidden = menu.classList.toggle("hidden");
        toggleBtn.setAttribute("aria-expanded", nowHidden ? "false" : "true");
      });
      document.addEventListener("click", function (e) {
        if (menu.classList.contains("hidden")) {
          return;
        }
        if (!menu.contains(e.target) && !toggleBtn.contains(e.target)) {
          menu.classList.add("hidden");
          toggleBtn.setAttribute("aria-expanded", "false");
        }
      });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && !menu.classList.contains("hidden")) {
          menu.classList.add("hidden");
          toggleBtn.setAttribute("aria-expanded", "false");
        }
      });
    }
  }

  ready(function () {
    Array.prototype.forEach.call(document.querySelectorAll("[data-cols-table]"), setupTable);
  });
})();
