use dnssec_prover::rr::{Name, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

use std::time::SystemTime;

use crate::HrnResolution;

pub fn resolve_proof(dns_name: &Name, proof: Vec<u8>) -> Result<HrnResolution, &'static str> {
	let rrs = parse_rr_stream(&proof)
		.map_err(|()| "DNS Proof Builder somehow generated an invalid proof")?;
	let verified_rrs = verify_rr_stream(&rrs).map_err(|_| "DNSSEC signatures were invalid")?;

	let clock_err =
		"DNSSEC validation relies on having a correct system clock. It is currently set before 1970.";
	let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|_| clock_err)?;

	if now.as_secs() < verified_rrs.valid_from {
		return Err("Some DNSSEC records are not yet valid. Check your system clock.");
	}
	if now.as_secs() > verified_rrs.expires {
		return Err("Some DNSSEC records are expired. Check your system clock.");
	}

	let resolved_rrs = verified_rrs.resolve_name(dns_name);

	let mut result = None;
	for rr in resolved_rrs {
		if let RR::Txt(txt) = rr {
			if result.is_some() {
				return Err("Multiple TXT records existed for the HRN, which is invalid");
			}
			result = Some(txt.data.as_vec());
		}
	}
	if let Some(res) = result {
		let result =
			String::from_utf8(res).map_err(|_| "TXT record contained an invalid string")?;
		Ok(HrnResolution { proof: Some(proof), result })
	} else {
		Err("No validated TXT record found")
	}
}
