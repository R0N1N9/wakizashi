(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.subnet." + k;
  const big = (n) => { n = BigInt(n); return n < 10n ** 15n ? W.fmt.num(Number(n)) : `2^${n.toString(2).length - 1}${(n & (n - 1n)) === 0n ? "" : "+"} (${n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")})`; };
  const mono = (s) => `<span class="mono break">${esc(s)}</span>`;

  W.tool("naginata", "subnet", {
    name: "Subnet", order: 20,
    desc: "IPv4 + IPv6 CIDR calculator — hosts, masks, binary view, splitting, supernets and range ↔ CIDR.",
    icon: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 12h18M12 3v18M7.5 7.5h0M16.5 16.5h0"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        let tab = W.store.get(K("tab"), "info");
        el.innerHTML = ui.head("Subnet", "Calculator", "Network math for scoping and planning — IPv4 and IPv6. Nothing is sent anywhere.") + `
          <div class="tabs" id="sn-tabs">${[["info", "Details"], ["split", "Split"], ["agg", "Supernet / aggregate"], ["range", "Range ↔ CIDR"]].map(([v, l]) => `<button data-tab="${v}" class="${v === tab ? "on" : ""}">${l}</button>`).join("")}</div>
          <div id="sn-body"></div>`;
        W.tabs($("#sn-tabs"), (t) => { tab = t; W.store.set(K("tab"), t); draw(); });
        const last = W.store.get(K("cidr"), "192.168.10.77/26");
        let initial = arg ? String(arg) : null;

        function draw() {
          const b = $("#sn-body");
          if (tab === "info") {
            b.innerHTML = `<div class="panel"><label class="lbl" for="sn-in">Address / CIDR</label>
              <div class="row"><input id="sn-in" type="text" style="flex:1;min-width:200px" spellcheck="false" autocapitalize="off" placeholder="10.0.0.0/8 · 192.168.1.10/27 · 2001:db8::/48 · 10.0.0.1 255.255.255.0">
              <button class="btn pri" id="sn-go">Calculate</button></div>
              <div class="row small muted" style="margin-top:8px">Try: ${["10.20.0.0/14", "172.16.5.4/31", "192.0.2.1", "2001:db8:abcd:12::1/56", "fe80::1/64"].map((x) => `<button class="chip" data-x="${x}">${x}</button>`).join("")}</div></div>
              <div id="sn-out"></div>`;
            const inp = $("#sn-in"); inp.value = initial || last; initial = null;
            const go = () => {
              let v = inp.value.trim();
              const mm = /^(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v);          // "addr netmask" form
              if (mm) { const m = W.eng.subnet.parseIPv4(mm[2]); if (m != null) { const bits = m.toString(2).replace(/0+$/, "").length; if (/^1*0*$/.test(m.toString(2).padStart(32, "0"))) v = `${mm[1]}/${m === 0n ? 0 : bits}`; } }
              try { const i = W.eng.subnet.info(v); W.store.set(K("cidr"), inp.value.trim()); drawInfo(i); }
              catch (e) { $("#sn-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; }
            };
            $("#sn-go").onclick = go; inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
            b.querySelectorAll("[data-x]").forEach((c) => (c.onclick = () => { inp.value = c.dataset.x; go(); }));
            go();
          } else if (tab === "split") {
            b.innerHTML = `<div class="panel"><div class="grid g3">
                <div><label class="lbl" for="sp-in">Network</label><input id="sp-in" type="text" spellcheck="false" autocapitalize="off"></div>
                <div><label class="lbl" for="sp-mode">Split by</label><select id="sp-mode"><option value="prefix">New prefix length</option><option value="count">Number of subnets</option><option value="hosts">Hosts per subnet (IPv4)</option></select></div>
                <div><label class="lbl" for="sp-n">Value</label><input id="sp-n" type="number" min="1" value="26"></div>
              </div><div class="spacer"></div><div class="row"><button class="btn pri" id="sp-go">Split</button><button class="btn ghost" id="sp-copy">${W.icon(W.I.copy)} Copy list</button></div></div><div id="sp-out"></div>`;
            $("#sp-in").value = W.store.get(K("split"), "10.0.0.0/24");
            let list = [];
            const go = () => {
              const net = $("#sp-in").value.trim(), mode = $("#sp-mode").value, n = +$("#sp-n").value;
              try {
                const c = W.eng.subnet.parseCidr(net); if (!c) throw new Error("enter a network in CIDR form");
                let r;
                if (mode === "count") r = W.eng.subnet.splitCount(net, n);
                else if (mode === "hosts") { if (c.v !== 4) throw new Error("hosts-per-subnet is for IPv4 — use a prefix length for IPv6"); let bits = 32; while (bits > 0 && ((2 ** (32 - bits)) - (bits >= 31 ? 0 : 2)) < n) bits--; r = W.eng.subnet.split(net, Math.max(bits, c.bits)); }
                else r = W.eng.subnet.split(net, n);
                W.store.set(K("split"), net);
                list = r.list.map((x) => x.cidr);
                const hostsEach = r.v === 4 ? (r.bits >= 31 ? r.size : r.size - 2n) : r.size;
                $("#sp-out").innerHTML = `<div class="grid g3">${ui.stat(big(r.count), "Subnets", true)}${ui.stat("/" + r.bits, "Prefix")}${ui.stat(big(hostsEach), r.v === 4 ? "Usable hosts each" : "Addresses each")}</div>`
                  + (r.truncated ? `<div class="callout warn">Showing the first ${W.fmt.num(r.list.length)} of ${big(r.count)} subnets.</div><div class="spacer"></div>` : "")
                  + ui.table(["#", "Subnet", "First", "Last"], r.list.map((x, i) => [String(i + 1), x.cidr, x.first, x.last]), { mono: true, max: 520 });
              } catch (e) { $("#sp-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; list = []; }
            };
            $("#sp-go").onclick = go; $("#sp-copy").onclick = () => (list.length ? W.copy(list.join("\n"), `${list.length} subnets copied`) : W.toast("Split first", 1));
            $("#sp-mode").onchange = () => { const m = $("#sp-mode").value; $("#sp-n").value = m === "prefix" ? 26 : m === "count" ? 4 : 50; go(); };
            go();
          } else if (tab === "agg") {
            b.innerHTML = `<div class="panel"><label class="lbl" for="ag-in">CIDRs, ranges or addresses — one per line</label>
              <textarea id="ag-in" rows="7" spellcheck="false" autocapitalize="off"></textarea><div class="spacer"></div>
              <div class="row"><button class="btn pri" id="ag-go">Summarise</button><button class="btn ghost" id="ag-copy">${W.icon(W.I.copy)} Copy aggregate</button></div></div><div id="ag-out"></div>`;
            $("#ag-in").value = W.store.get(K("agg"), "192.168.0.0/24\n192.168.1.0/24\n192.168.2.0/23\n10.0.0.5-10.0.0.20\n2001:db8::/33\n2001:db8:8000::/33");
            let agg = [];
            const go = () => {
              const items = $("#ag-in").value.split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
              W.store.set(K("agg"), $("#ag-in").value);
              const a = W.eng.subnet.aggregate(items), s = W.eng.subnet.supernet(items);
              agg = a.cidrs;
              $("#ag-out").innerHTML = (a.invalid.length ? `<div class="callout bad">Ignored: ${a.invalid.map(esc).join(", ")}</div><div class="spacer"></div>` : "")
                + `<div class="grid g2">${ui.panel("Minimal aggregate (exact)", a.cidrs.length ? `<pre class="out">${esc(a.cidrs.join("\n"))}</pre><p class="small muted">${a.cidrs.length} CIDR(s) covering exactly the same addresses.</p>` : ui.empty("NOTHING TO SUMMARISE"))}
                ${ui.panel("Single supernet", s.supernets.length ? s.supernets.map((x) => ui.kv([["IPv" + x.v, x.cidr], ["Size", big(x.size)], ["Covered", big(x.covered)], ["Extra", big(x.extra) + (x.extra ? " addresses not in your list" : " — exact fit")]])
                  + (x.extra ? `<div class="callout warn small" style="margin-top:8px">The supernet pulls in addresses you didn't list — don't use it as scope without confirming them.</div>` : "")).join('<div class="spacer"></div>') : ui.empty("—"))}</div>`;
            };
            $("#ag-go").onclick = go; $("#ag-copy").onclick = () => (agg.length ? W.copy(agg.join("\n")) : W.toast("Nothing yet", 1));
            go();
          } else {
            b.innerHTML = `<div class="grid g2"><div class="panel"><h2>Range → CIDR</h2>
                <div class="grid g2"><div><label class="lbl" for="rg-a">First address</label><input id="rg-a" type="text" spellcheck="false" autocapitalize="off"></div>
                <div><label class="lbl" for="rg-b">Last address</label><input id="rg-b" type="text" spellcheck="false" autocapitalize="off"></div></div>
                <div class="spacer"></div><button class="btn pri" id="rg-go">Convert</button><div class="spacer"></div><div id="rg-out"></div></div>
              <div class="panel"><h2>CIDR → range</h2><label class="lbl" for="cr-in">CIDR</label>
                <div class="row"><input id="cr-in" type="text" style="flex:1;min-width:160px" spellcheck="false" autocapitalize="off"><button class="btn pri" id="cr-go">Convert</button></div>
                <div class="spacer"></div><div id="cr-out"></div></div></div>`;
            $("#rg-a").value = "10.0.0.5"; $("#rg-b").value = "10.0.0.130"; $("#cr-in").value = "172.16.4.0/22";
            const rg = () => { try { const l = W.eng.subnet.rangeToCidrs($("#rg-a").value.trim(), $("#rg-b").value.trim()); $("#rg-out").innerHTML = `<pre class="out">${esc(l.join("\n"))}</pre><div class="row" style="margin-top:8px"><span class="small muted">${l.length} CIDR block(s)</span><button class="btn ghost sm" id="rg-copy">${W.icon(W.I.copy)} Copy</button></div>`; $("#rg-copy").onclick = () => W.copy(l.join("\n")); } catch (e) { $("#rg-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; } };
            const cr = () => { try { const r = W.eng.subnet.cidrToRange($("#cr-in").value.trim()); $("#cr-out").innerHTML = ui.kv([["Start", r.start], ["End", r.end], ["Addresses", big(r.size)], ["Range", `${r.start} - ${r.end}`]]); } catch (e) { $("#cr-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; } };
            $("#rg-go").onclick = rg; $("#cr-go").onclick = cr; rg(); cr();
          }
        }

        function drawInfo(i) {
          const rows = i.v === 4 ? [
            ["CIDR", i.cidr], ["Network", i.network], ["Broadcast", i.broadcast || "— (point-to-point /31 or host /32)"], ["First host", i.first], ["Last host", i.lastHost],
            ["Usable hosts", big(i.hosts)], ["Total addresses", big(i.total)], ["Netmask", i.netmask], ["Wildcard", i.wildcard], ["Type", i.type], ["Class", i.cls],
            ["Integer / hex", `${i.int} · ${i.hex}`], ["Reverse DNS", i.arpa],
          ] : [
            ["CIDR", i.cidr], ["Network", i.network], ["Last address", i.last], ["Addresses", big(i.total)], ["/64 networks", i.bits <= 64 ? big(i.slash64s) : "— (smaller than a /64)"],
            ["Prefix mask", i.netmask], ["Type", i.type], ["Address (expanded)", i.expanded], ["Network (expanded)", i.networkExpanded], ["Last (expanded)", i.lastExpanded], ["Reverse DNS", i.arpa],
          ];
          const binRows = Object.entries(i.binary).map(([k, v]) => [k, v]);
          $("#sn-out").innerHTML = (i.hostBits ? `<div class="callout warn small">${esc(i.address)} has host bits set — the network is ${esc(i.cidr)}.</div><div class="spacer"></div>` : "")
            + `<div class="grid g4">${ui.stat("/" + i.bits, "Prefix", true)}${ui.stat(i.v === 4 ? big(i.hosts) : "2^" + (128 - i.bits), i.v === 4 ? "Usable hosts" : "Addresses")}${ui.stat("IPv" + i.v, "Family")}<div class="panel stat"><div class="n" style="font-size:17px;line-height:1.25;overflow-wrap:anywhere">${esc(i.type.replace(/ \(.*\)$/, ""))}</div><div class="l">Type</div></div></div>
            <div class="grid g2">${ui.panel("Details", `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono break">${esc(v)}</dd>`).join("")}</dl>
              <div class="spacer"></div><div class="row"><button class="btn ghost sm" id="sn-copy">${W.icon(W.I.copy)} Copy</button><button class="btn ghost sm" id="sn-scope">Check scope</button><button class="btn ghost sm" id="sn-split">Split…</button></div>`)}
            ${ui.panel("Binary", binRows.map(([k, v]) => `<div class="lbl" style="margin-top:6px">${esc(k)}</div>${binView(v, i.bits, i.v)}`).join("")
              + `<p class="tiny muted">Network bits in accent colour, host bits dimmed.</p>`)}</div>`;
          $("#sn-copy").onclick = () => W.copy(rows.map(([k, v]) => `${k}: ${v}`).join("\n"));
          $("#sn-scope").onclick = () => W.go("naginata", "scope", i.cidr);
          $("#sn-split").onclick = () => { W.store.set(K("split"), i.cidr); tab = "split"; W.store.set(K("tab"), tab); $$tab(); draw(); };
        }
        const $$tab = () => W.$$("#sn-tabs button").forEach((x) => x.classList.toggle("on", x.dataset.tab === tab));
        function binView(s, bits, v) {
          let seen = 0, out = "";
          for (const ch of s) { if (ch === "." || ch === ":") { out += `<span class="faint">${ch}</span>`; continue; } out += seen < bits ? `<span class="c-acc">${ch}</span>` : `<span class="faint">${ch}</span>`; seen++; }
          return `<div class="mono break" style="font-size:${v === 4 ? 13 : 11.5}px;line-height:1.5">${out}</div>`;
        }
        draw();
      });
    },
  });
})();
