const data = $input.first().json;

if (
  !Array.isArray(data.hosts) ||
  data.hosts.length === 0
) {
  throw new Error(
    'Esta rama requiere al menos un host autorizado'
  );
}

const payload = {
  target_id: data.target_id,
  run_id: data.run_id,
  hosts: data.hosts,
  candidates: data.candidates,
  pending: data.pending,
  rejected: data.rejected,
  counts: data.counts,
  normalization_ms: data.normalization_ms
};

const payload_b64 = Buffer
  .from(JSON.stringify(payload), 'utf8')
  .toString('base64');

if (payload_b64.length > 60000) {
  throw new Error(
    'Los datos superan el límite del prototipo; usar lotes o transferencia de archivos'
  );
}

return [
  {
    json: {
      ...data,
      status: 'ready_for_probe',
      payload_b64
    }
  }
];