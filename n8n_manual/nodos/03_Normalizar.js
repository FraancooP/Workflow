const data = $input.first().json;
const started = Date.now();

if (
  !Array.isArray(data.raw) ||
  !data.scope ||
  typeof data.scope.domain !== 'string' ||
  !Array.isArray(data.scope.allowed_hosts)
) {
  throw new Error('Faltan registros o configuración de alcance');
}

const domain = data.scope.domain;
const allowed = new Set(data.scope.allowed_hosts);
const unique = new Map();
const rejected = [];
let acceptedRecords = 0;

function validHost(host) {
  if (host.length > 253) return false;

  const labels = host.split('.');
  const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  return (
    labels.length >= 2 &&
    labels.every(label => labelPattern.test(label))
  );
}

for (const row of data.raw) {
  if (
    !row ||
    typeof row.value !== 'string' ||
    typeof row.source !== 'string'
  ) {
    rejected.push({ original: row, reason: 'invalid_record' });
    continue;
  }

  const host = row.value.trim().toLowerCase().replace(/\.$/, '');

  // Un comodín de certificado no identifica un host concreto.
  if (host.includes('*')) {
    rejected.push({
      ...row,
      normalized: host,
      reason: 'wildcard_not_concrete_host',
    });
    continue;
  }

  if (!validHost(host)) {
    rejected.push({
      ...row,
      normalized: host,
      reason: 'invalid_syntax',
    });
    continue;
  }

  if (host !== domain && !host.endsWith('.' + domain)) {
    rejected.push({
      ...row,
      normalized: host,
      reason: 'outside_domain',
    });
    continue;
  }

  acceptedRecords++;

  if (!unique.has(host)) {
    unique.set(host, {
      host,
      sources: [],
      providers: [],
    });
  }

  const candidate = unique.get(host);

  if (!candidate.sources.includes(row.source)) {
    candidate.sources.push(row.source);
  }

  const providers = Array.isArray(row.providers)
    ? row.providers
    : typeof row.providers === 'string'
      ? [row.providers]
      : [];

  for (const provider of providers) {
    if (
      typeof provider === 'string' &&
      !candidate.providers.includes(provider)
    ) {
      candidate.providers.push(provider);
    }
  }
}

const candidates = [...unique.values()]
  .sort((a, b) => a.host.localeCompare(b.host))
  .map(candidate => ({
    ...candidate,
    discovered: candidate.sources.some(
      source => source === 'subfinder' || source === 'crtsh'
    ),
    provided_target: candidate.sources.includes('provided_target'),
  }));

// Solo estos hosts podrán pasar a las comprobaciones activas.
const hosts = candidates.filter(candidate => allowed.has(candidate.host));
const pending = candidates.filter(candidate => !allowed.has(candidate.host));

if (hosts.length > 500) {
  throw new Error('Más de 500 hosts autorizados: implementar lotes');
}

const discovered = candidates.filter(candidate => candidate.discovered);

const counts = {
  raw: data.raw.length,
  rejected: rejected.length,
  accepted_records: acceptedRecords,
  duplicates: acceptedRecords - candidates.length,
  unique_candidates: candidates.length,
  authorized_hosts: hosts.length,
  pending_authorization: pending.length,

  discovered_unique: discovered.length,
  subfinder_unique: candidates.filter(
    candidate => candidate.sources.includes('subfinder')
  ).length,
  crtsh_unique: candidates.filter(
    candidate => candidate.sources.includes('crtsh')
  ).length,
  discovered_by_both: candidates.filter(
    candidate =>
      candidate.sources.includes('subfinder') &&
      candidate.sources.includes('crtsh')
  ).length,
  provided_only: candidates.filter(
    candidate => candidate.provided_target && !candidate.discovered
  ).length,
};

return [{
  json: {
    ...data,
    candidates,
    hosts,
    pending,
    rejected,
    counts,
    normalization_ms: Date.now() - started,
  },
}];