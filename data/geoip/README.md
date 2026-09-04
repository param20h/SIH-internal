# GeoLite2 database

TVA's IP-geolocation enrichment reads a local `GeoLite2-City.mmdb` file from
this directory. It is deliberately not committed to the repository (MaxMind's
license permits redistribution only under its own terms), so it must be
placed here before enrichment will return live data:

1. Create a free MaxMind account and generate a license key:
   https://www.maxmind.com/en/geolite2/signup
2. Download `GeoLite2-City.mmdb` and place it at `data/geoip/GeoLite2-City.mmdb`.

If the file is absent, the enrichment stage degrades gracefully: hop
geolocation fields are omitted and the API response marks that indicator as
unavailable rather than failing the analysis. The deterministic layer
(parsing, SPF/DKIM/DMARC, relay-chain anomaly detection) never depends on
this file and remains 100% functional without it.
