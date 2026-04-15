/// Enrichment pipeline — runs after normalization.
///
/// Phase 1 enrichments:
/// 1. GeoIP (MaxMind GeoLite2-City) for external IP addresses.
/// 2. Asset resolution (stub — full implementation in ace-asset-inventory Phase 2).
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use maxminddb::{geoip2, Reader as MmReader};
use tracing::{debug, warn};

use crate::schema::AceEvent;

// ─────────────────────────────────────────────────────────────
//  GeoIP enricher
// ─────────────────────────────────────────────────────────────

pub struct GeoIpEnricher {
    reader: Arc<MmReader<Vec<u8>>>,
}

impl GeoIpEnricher {
    /// Load a MaxMind `.mmdb` database from disk.  Returns `None` if the
    /// file does not exist (GeoIP enrichment is optional in dev mode).
    pub fn load(path: impl AsRef<Path>) -> Option<Self> {
        match MmReader::open_readfile(path) {
            Ok(r) => {
                debug!("GeoIP database loaded");
                Some(Self { reader: Arc::new(r) })
            }
            Err(e) => {
                warn!("GeoIP database not available: {e}");
                None
            }
        }
    }

    /// Look up a string IP address and return `(country_iso, asn)`.
    fn lookup(&self, ip_str: &str) -> Option<(Option<String>, Option<String>)> {
        let ip: IpAddr = IpAddr::from_str(ip_str).ok()?;

        // Skip RFC 1918 and loopback.
        if is_private(ip) {
            return None;
        }

        let city: geoip2::City = self.reader.lookup(ip).ok()?;
        let country = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(String::from);

        // For ASN we'd need a separate GeoLite2-ASN database.
        Some((country, None))
    }

    /// Enrich a mutable `AceEvent` in-place.
    pub fn enrich(&self, event: &mut AceEvent) {
        if let Some(src_ip) = &event.normalized.src_ip.clone() {
            if let Some((country, asn)) = self.lookup(src_ip) {
                event.normalized.src_country = country;
                event.normalized.src_asn     = asn;
            }
        }
        if let Some(dst_ip) = &event.normalized.dst_ip.clone() {
            if let Some((country, asn)) = self.lookup(dst_ip) {
                event.normalized.dst_country = country;
                event.normalized.dst_asn     = asn;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Asset resolver (Phase 1 stub)
// ─────────────────────────────────────────────────────────────

pub struct AssetResolver;

impl AssetResolver {
    pub fn new() -> Self {
        Self
    }

    /// Stub: in Phase 2 this calls ace-asset-inventory via gRPC.
    /// For now, just return None (no asset ID assigned).
    pub fn resolve(&self, event: &mut AceEvent) {
        event.source_asset_id = None;
    }
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ─────────────────────────────────────────────────────────────
//  Combined pipeline
// ─────────────────────────────────────────────────────────────

pub struct EnrichmentPipeline {
    geoip: Option<GeoIpEnricher>,
    asset: AssetResolver,
}

impl EnrichmentPipeline {
    pub fn new(geoip_db_path: Option<&str>) -> Self {
        let geoip = geoip_db_path.and_then(GeoIpEnricher::load);
        Self {
            geoip,
            asset: AssetResolver::new(),
        }
    }

    pub fn run(&self, event: &mut AceEvent) {
        if let Some(g) = &self.geoip {
            g.enrich(event);
        }
        self.asset.resolve(event);
    }
}
