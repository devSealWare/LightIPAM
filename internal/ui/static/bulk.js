/* Light IPAM — bulk edit (multi-select row actions).
 *
 * Progressive enhancement: the tables render full server-side and the action
 * bar is always present, so with JS disabled an operator checks rows, picks an
 * action, fills the matching field, and submits. When enabled, this wires the
 * select-all checkbox, a live selection count, disables Apply until a row and an
 * action are chosen, and shows only the chosen action's contextual field.
 *
 * Markup contract (set in the templates):
 *   [data-bulk-form]              the <form> wrapping one table
 *   [data-bulk-checkbox]          a row checkbox (name="ids")
 *   [data-bulk-all]               the select-all checkbox
 *   [data-bulk-count]             element whose text shows the selected count
 *   [data-bulk-action]            the action <select name="action">
 *   [data-bulk-field="a b"]       a field shown only for the listed actions
 *   [data-bulk-apply]             the submit button
 */
(function () {
  "use strict";

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  function setupForm(form) {
    var boxes = Array.prototype.slice.call(form.querySelectorAll("[data-bulk-checkbox]"));
    if (!boxes.length) {
      return;
    }
    var all = form.querySelector("[data-bulk-all]");
    var countEl = form.querySelector("[data-bulk-count]");
    var actionSel = form.querySelector("[data-bulk-action]");
    var applyBtn = form.querySelector("[data-bulk-apply]");
    var fields = Array.prototype.slice.call(form.querySelectorAll("[data-bulk-field]"));

    function selected() {
      var n = 0;
      boxes.forEach(function (b) {
        if (b.checked) {
          n++;
        }
      });
      return n;
    }

    function refresh() {
      var n = selected();
      if (countEl) {
        countEl.textContent = String(n);
      }
      if (all) {
        all.checked = n > 0 && n === boxes.length;
        all.indeterminate = n > 0 && n < boxes.length;
      }
      if (applyBtn) {
        var ready = n > 0 && (!actionSel || actionSel.value !== "");
        applyBtn.disabled = !ready;
      }
    }

    function showFields() {
      var action = actionSel ? actionSel.value : "";
      fields.forEach(function (field) {
        var forActions = (field.getAttribute("data-bulk-field") || "").split(/\s+/);
        field.style.display = forActions.indexOf(action) !== -1 ? "" : "none";
      });
    }

    if (all) {
      all.addEventListener("change", function () {
        boxes.forEach(function (b) {
          b.checked = all.checked;
        });
        refresh();
      });
    }
    boxes.forEach(function (b) {
      b.addEventListener("change", refresh);
    });
    if (actionSel) {
      actionSel.addEventListener("change", function () {
        showFields();
        refresh();
      });
    }

    showFields();
    refresh();
  }

  ready(function () {
    Array.prototype.forEach.call(document.querySelectorAll("[data-bulk-form]"), setupForm);
  });
})();
