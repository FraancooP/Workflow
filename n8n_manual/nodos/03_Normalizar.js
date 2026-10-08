const data = $input.first().json;
const started = Date.now();

if (
  !Array.isArray(data.raw) ||
  !data.scope ||
  !Array.isArray(data.scope.allowed_hosts)
) {
  throw new Error(
    'Faltan los registros o la configuración de alcance'
  );
}

const domain = data.scope.domain;

const allowed = new Set(data.scope.allowed_hosts);

const unique = new Map();
const rejected = [];

let acceptedRecords = 0;


function validHost(host) {
  if (host.length > 253) {
    return false;
  }

  const labels = host.split('.');

  if (labels.length < 2) {
    return false;
  }

  return labels.every(label =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
  );
}


for (const row of data.raw) {
  if (
    !row ||
    typeof row.value !== 'string' ||
    typeof row.source !== 'string'
  ) {
    throw new Error(
      'Registro sin value y source de tipo texto'
    );
  }

  const host = row.value
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\*\./, '');

  if (!validHost(host)) {
    rejected.push({
      ...row,
      normalized: host,
      reason: 'invalid_syntax'
    });

    continue;
  }

  if (
    !(host === domain || host.endsWith('.' + domain))
  ) {
    rejected.push({
      ...row,
      normalized: host,
      reason: 'outside_domain'
    });

    continue;
  }

  acceptedRecords++;

  if (!unique.has(host)) {
    unique.set(host, {
      host,
      sources: []
    });
  }

  const record = unique.get(host);

  if (!record.sources.includes(row.source)) {
    record.sources.push(row.source);
  }
}


const candidates = [...unique.values()].sort(
  (a, b) => a.host.localeCompare(b.host)
);

if (candidates.length > 500) {
  throw new Error(
    'Más de 500 candidatos: acotar el alcance o implementar lotes'
  );
}

const hosts = candidates.filter(
  row => allowed.has(row.host)
);

const pending = candidates.filter(
  row => !allowed.has(row.host)
);

const counts = {
  raw: data.raw.length,
  rejected: rejected.length,
  accepted_records: acceptedRecords,
  duplicates: acceptedRecords - candidates.length,
  unique_candidates: candidates.length,
  authorized_hosts: hosts.length,
  pending_authorization: pending.length
};

return [
  {
    json: {
      ...data,
      candidates,
      hosts,
      pending,
      rejected,
      counts,
      normalization_ms: Date.now() - started
    }
  }
];