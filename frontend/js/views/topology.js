/**
 * Screen 6 — the topology and violation map.
 *
 * The honest caveat comes first, because this is the screen most likely to be
 * mistaken for something it is not: **PRAMAN does no network discovery.** It reads
 * configuration files. So the adjacency drawn here is *inferred* — two devices are
 * linked when their interfaces sit in the same IP subnet, which is a strong hint
 * and not a cable. A device whose neighbour was never uploaded appears unlinked,
 * and that is a gap in the corpus rather than a gap in the network.
 *
 * Saying so on the screen matters more than it might seem. A map that looks
 * discovered invites an operator to read absence as "not connected", and in a
 * compliance tool the difference between "no adjacency found" and "no adjacency
 * exists" is the difference between a finding and a guess.
 *
 * Node colour is deliberately pessimistic: one high-severity failure makes a node
 * red however many controls passed, because that is the finding that gets someone
 * called at night. The failure count is printed inside the node so the status
 * survives a monochrome print or a colour-vision difference.
 */

import { el, table, num, pill, emptyState, spinner, clear, pct, count, agree } from '../dom.js';
import { store, page, panel, button, navigate, select } from '../shell.js';
import { topologyMap, nodeStatus, deviceHeatmap, controlFamily } from '../charts.js';
import { NODE_STATUS_COLORS } from '../palette.js';
import * as api from '../api.js';

/** Devices whose ids are security-test artefacts rather than real inventory.
 *
 * The corpus contains rows deliberately created by the path-traversal tests. They
 * prove the defence works and they are not devices; drawing them on a topology map
 * would put `../../../../etc/evil` next to a router. They are counted and named in
 * a note instead of being silently dropped — a filtered-out row that nobody
 * mentions is how a tool starts lying about its own inventory.
 */
function looksSynthetic(device) {
  const id = String(device.device_id || '');
  return id.includes('/') || id.includes('\\') || id.includes('..');
}

/** Parse `"10.0.1.1 255.255.255.252"` into its network address.
 *
 * Returns null on anything that is not a dotted quad with a dotted mask — a
 * DHCP-assigned interface, an unnumbered one, an IPv6 address. Returning null
 * rather than guessing keeps a malformed value from inventing an edge.
 */
function networkOf(value) {
  const text = String(value || '').trim();
  const parts = text.split(/\s+/);
  if (parts.length < 2) return null;

  const octets = parts[0].split('.').map(Number);
  const mask = parts[1].split('.').map(Number);
  if (octets.length !== 4 || mask.length !== 4) return null;
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  if (mask.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;

  const bits = mask.reduce((acc, byte) => acc + byte.toString(2).split('1').length - 1, 0);
  // A /32 is a loopback or a host route: every device has one and linking on it
  // would draw a complete graph that means nothing.
  if (bits >= 31 || bits === 0) return null;

  const network = octets.map((byte, index) => byte & mask[index]).join('.');
  return `${network}/${bits}`;
}

export async function topologyView({ outlet }) {
  const devicesBody = await store.devices();
  const all = devicesBody.devices || [];
  const synthetic = all.filter(looksSynthetic);
  const devices = all.filter((device) => !looksSynthetic(device));

  const host = el('div', {});
  let scope = 'audited';

  async function load() {
    clear(host);
    host.appendChild(spinner(`Loading findings for ${count(devices.length, 'device')}…`));

    const pool = scope === 'audited' ? devices.filter((device) => device.latest_audit_id) : devices;

    // Sequential rather than Promise.all: this is one request per device against a
    // single-writer SQLite database, and a dozen concurrent full-device reads is a
    // measurable stall for no gain on a local server.
    const loaded = [];
    for (const device of pool) {
      try {
        loaded.push(await api.device(device.device_id));
      } catch {
        // A device that cannot be read is reported in the note below, not skipped
        // silently — a map missing a node without explanation is worse than a gap.
        loaded.push({ device, __unreadable: true });
      }
    }

    clear(host);
    host.appendChild(draw(loaded, pool));
  }

  function draw(loaded, pool) {
    const unreadable = loaded.filter((entry) => entry.__unreadable);
    const usable = loaded.filter((entry) => !entry.__unreadable);

    const nodes = usable.map((detail) => {
      const findings = detail.findings || [];
      const status = nodeStatus(findings);
      const subnets = new Set();
      for (const fact of detail.facts || []) {
        if (fact.path !== 'interface.ip_address' || fact.present === false) continue;
        const network = networkOf(fact.value);
        if (network) subnets.add(network);
      }
      return {
        device_id: detail.device.device_id,
        hostname: detail.device.hostname || detail.device.device_id,
        vendor: detail.device.vendor,
        subnets,
        neighbours: [],
        ...status,
      };
    });

    // Edges from shared subnets. A subnet with one device on it produces nothing;
    // a subnet with three produces a triangle, which is what "these three share a
    // broadcast domain" actually looks like.
    const bySubnet = new Map();
    for (const node of nodes) {
      for (const subnet of node.subnets) {
        if (!bySubnet.has(subnet)) bySubnet.set(subnet, []);
        bySubnet.get(subnet).push(node);
      }
    }

    const edges = [];
    const seen = new Set();
    for (const [subnet, members] of [...bySubnet.entries()].sort()) {
      if (members.length < 2) continue;
      for (let i = 0; i < members.length; i += 1) {
        for (let j = i + 1; j < members.length; j += 1) {
          // NUL as the delimiter, because a device_id cannot contain one, so no pair
          // of ids can collide into the same key. Written as an escape rather
          // than a literal byte: a raw NUL makes this file binary to grep and
          // diff, which is how three un-pluralised counts below survived a
          // project-wide sweep that found the other twenty.
          const key = [members[i].device_id, members[j].device_id].sort().join('\u0000');
          if (seen.has(key)) continue;
          seen.add(key);
          edges.push({ from: members[i].device_id, to: members[j].device_id, label: `shared subnet ${subnet}` });
          members[i].neighbours.push(members[j].hostname);
          members[j].neighbours.push(members[i].hostname);
        }
      }
    }

    const map = topologyMap(nodes, edges, {
      onSelect: (node) => navigate('device', [node.device_id], { result: 'fail' }),
      subtitle: edges.length
        ? `${count(edges.length, 'link')} inferred from shared IP subnets — configuration evidence, not discovery. Click a node for its failing controls.`
        : 'No two devices share an IP subnet in the uploaded configurations, so no adjacency can be inferred. Upload both ends of a link to see it.',
    });

    // The per-device heatmap belongs here rather than on the dashboard: it answers
    // "which family is weak across the estate", which is the same question the map
    // answers spatially.
    const heatRows = usable.map((detail) => {
      const families = {};
      for (const finding of detail.findings || []) {
        const result = String(finding.result || '').toLowerCase();
        if (result !== 'pass' && result !== 'fail') continue;
        const family = controlFamily(finding);
        if (!families[family]) families[family] = { pass: 0, fail: 0 };
        families[family][result] += 1;
      }
      return { hostname: detail.device.hostname || detail.device.device_id, device_id: detail.device.device_id, families };
    });

    const counts = nodes.reduce(
      (acc, node) => {
        acc[node.status] += 1;
        return acc;
      },
      { green: 0, amber: 0, red: 0 }
    );

    return el(
      'div',
      {},
      panel(
        null,
        el(
          'div',
          { class: 'stat-grid stat-grid-tight' },
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Devices on the map' }),
            el('div', { class: 'stat-value', text: num(nodes.length) }),
            el('div', { class: 'stat-hint', text: scope === 'audited' ? 'committed audits only' : 'every ingested device' })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'High-severity failures' }),
            el('div', { class: 'stat-value stat-bad', text: num(counts.red) }),
            el('div', { class: 'stat-hint', text: 'devices with at least one' })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Low or medium only' }),
            el('div', { class: 'stat-value', text: num(counts.amber) })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Everything applicable passes' }),
            el('div', { class: 'stat-value', text: num(counts.green) })
          ),
          el(
            'div',
            { class: 'stat' },
            el('div', { class: 'stat-label', text: 'Inferred links' }),
            el('div', { class: 'stat-value', text: num(edges.length) }),
            el('div', { class: 'stat-hint', text: `${count(bySubnet.size, 'distinct subnet')} seen` })
          )
        )
      ),
      panel(
        'Map',
        nodes.length
          ? map
          : emptyState(
              scope === 'audited' ? 'No device has a committed audit yet.' : 'No devices have been ingested.',
              scope === 'audited'
                ? 'Switch the scope to "every ingested device" to see devices whose verdicts are computed but not committed.'
                : 'Upload a configuration to put the first device on the map.'
            ),
        el('p', {
          class: 'panel-note',
          text:
            'PRAMAN reads configuration files; it does not probe the network. An edge here means two devices have an ' +
            'interface in the same IP subnet, which is evidence of adjacency rather than proof of a cable. A device ' +
            'whose neighbour was never uploaded is drawn unlinked — that is a gap in what you gave the tool, not a ' +
            'statement about the network.',
        })
      ),
      heatRows.length
        ? panel(
            'Where the estate is weak',
            deviceHeatmap(heatRows) ||
              emptyState('No control family has a decided verdict on any device yet.'),
            el('p', {
              class: 'panel-note',
              text:
                'Pass rate per device and control family, over decided controls only. A family nobody could decide is ' +
                'drawn as an outline rather than the palest blue, because the palest blue means "checked, and clean".',
            })
          )
        : null,
      nodes.length
        ? panel(
            'Devices by risk',
            table(
              ['Device', 'Vendor', 'Status', 'High', 'Failing', 'Decided', 'Pass rate', 'Inferred neighbours'],
              nodes
                .slice()
                .sort((a, b) => b.high - a.high || b.fail - a.fail || String(a.hostname).localeCompare(String(b.hostname)))
                .map((node) => [
                  el('button', {
                    class: 'link-btn',
                    type: 'button',
                    text: node.hostname,
                    onclick: () => navigate('device', [node.device_id], { result: 'fail' }),
                  }),
                  el('span', { text: node.vendor || '—' }),
                  pill(
                    node.status === 'red' ? 'high-severity' : node.status === 'amber' ? 'low or medium' : 'clean',
                    NODE_STATUS_COLORS[node.status],
                    'pill-tiny'
                  ),
                  el('span', { text: num(node.high) }),
                  el('span', { text: num(node.fail) }),
                  el('span', { text: num(node.decided) }),
                  el('span', { text: node.decided ? pct((node.decided - node.fail) / node.decided, 0) : '—' }),
                  node.neighbours.length
                    ? el('span', { class: 'dim', text: [...new Set(node.neighbours)].join(', ') })
                    : el('span', { class: 'dim', text: 'none inferred' }),
                ]),
              { caption: 'Worst first — high-severity failures, then total failures.' }
            )
          )
        : null,
      unreadable.length
        ? panel(
            `Devices that could not be read (${num(unreadable.length)})`,
            el('p', {
              class: 'panel-note panel-warn',
              text: `${unreadable.map((entry) => entry.device.device_id).join(', ')} — these are absent from the map above. A missing node with no explanation would be worse than this note.`,
            })
          )
        : null,
      synthetic.length
        ? panel(
            `Excluded from the map (${num(synthetic.length)})`,
            el('p', {
              class: 'panel-note',
              text:
                'These rows were created by the path-traversal security tests and are not devices. They are excluded ' +
                'from the map rather than deleted, because they are evidence the traversal defence works: ' +
                `${synthetic.map((device) => device.device_id).join(', ')}.`,
            })
          )
        : null,
      pool.length < devices.length
        ? el('p', {
            class: 'panel-note',
            text: `${count(devices.length - pool.length, 'ingested device')} ${agree(devices.length - pool.length, 'is', 'are')} not shown because ${agree(devices.length - pool.length, 'it has', 'they have')} no committed audit.`,
          })
        : null
    );
  }

  const scopeSelect = select(
    'Scope',
    [
      ['audited', 'devices with a committed audit'],
      ['all', 'every ingested device'],
    ],
    scope,
    async (value) => {
      scope = value;
      await load();
    }
  );

  await load();

  return void outlet.replaceChildren(
    page(
      'Topology',
      'Inferred adjacency, coloured by compliance risk',
      [button('Devices', () => navigate('devices'), { class: 'btn-quiet' })],
      panel(null, el('div', { class: 'filter-bar' }, scopeSelect)),
      host
    )
  );
}
