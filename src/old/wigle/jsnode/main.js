// from https://github.com/nfvs/wigle-api
// have not work so far

var wigle = require('wigle-api');
var client = wigle.createClient(
    'username',
    'password'
);

client.query({
  ssid: "linksys",
  offset: 100
}, function(err, result) {
  if (err) throw err;
  console.log('Timestamp:', r.timestamp);
  console.log('Number of networks found:', r.networks.length);
  console.log('Networks:', r.networks);
});
