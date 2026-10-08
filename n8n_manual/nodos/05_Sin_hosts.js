const data = $input.first().json;

if (
  !Array.isArray(data.hosts) ||
  data.hosts.length !== 0
) {
  throw new Error(
    'Esta rama requiere una lista de hosts vacía'
  );
}

return [
  {
    json: {
      ...data,
      status: 'no_authorized_hosts',
      message: 'No hay hosts autorizados para la comprobación activa',
      records: [],
      check_performed: false
    }
  }
];