Package.describe({
  summary: "XXX descr"
});

Package.on_use(function(api) {
  api.use('accounts', ['client', 'server']);
  api.use('srp', ['client', 'server']);

  api.add_files('passwords_server.js', 'server');
  api.add_files('passwords_client.js', 'client');
  api.add_files('passwords_common.js', ['server', 'client']);
});

