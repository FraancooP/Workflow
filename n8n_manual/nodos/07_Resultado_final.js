const data = $input.first().json;
const inicio = $('INICIO').first().json;
const collection = $('INTERPRETAR SALIDA').first().json;

if (
  data.target_id !== inicio.target_id ||
  data.run_id !== inicio.run_id ||
  collection.run_id !== inicio.run_id
) {
  throw new Error(
    'Los datos no corresponden a la misma corrida'
  );
}

if (!Array.isArray(data.records)) {
  throw new Error('Falta la lista records');
}

if (
  !Number.isFinite(inicio.started_ms) ||
  !data.counts ||
  !data.scope
) {
  throw new Error(
    'Faltan datos de inicio, conteos o alcance'
  );
}

const allowedStatuses = [
  'completed',
  'partial',
  'no_authorized_hosts'
];

if (!allowedStatuses.includes(data.status)) {
  throw new Error(
    'Estado de finalización no reconocido'
  );
}

const records = data.records;
const finishedMs = Date.now();

const resolved = records.filter(
  row => row.dns_status === 'resolved'
).length;

const responding = records.filter(
  row => row.http_observed === true
).length;

const report = {
  schema_version: '1.0',

  target_id: data.target_id,
  run_id: data.run_id,

  status: data.status,
  check_performed: data.check_performed === true,

  started_at: inicio.started_at,
  collected_at: collection.collected_at,
  result_prepared_at: new Date(finishedMs).toISOString(),

  scope: data.scope,
  sources: collection.sources,

  counts: {
    ...data.counts,
    checked_records: records.length,
    dns_resolved: resolved,
    http_responding: responding
  },

  timings_ms: {
    collection: collection.collection_ms,
    normalization: data.normalization_ms,
    dns: data.dns_ms ?? null,
    httpx: data.httpx_ms ?? null,
    probe: data.probe_ms ?? null,
    until_result: finishedMs - inicio.started_ms
  },

  raw: collection.raw,
  candidates: data.candidates,
  authorized_hosts: data.hosts,
  pending_authorization: data.pending,
  rejected: data.rejected,

  records,

  diagnostics: {
    httpx_status: data.httpx_status ?? 'not_run',
    parse_errors: data.parse_errors ?? [],
    message: data.message ?? null
  }
};

return [{ json: report }];