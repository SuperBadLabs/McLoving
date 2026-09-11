//! Pre-user-namespace custody for the closed source launcher. Root ownership
//! is proved before UID translation; the child consumes held original files.
//! An immutable manifest alone is insufficient: receive verifies the live
//! same-sealed-image supervisor lineage before accepting any custody claim.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    RuntimeCustody, select_source_profile, verify_source_parent, verify_source_profile,
};

#[cfg(not(target_os = "linux"))]
pub struct RuntimeCustody {
    _private: (),
}
