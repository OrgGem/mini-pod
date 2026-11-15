//! Target guest CPU architecture definitions for VM images and runtime bundles.

use std::fmt;
use std::str::FromStr;

use crate::error::SandboxError;

/// Supported guest CPU architectures for portable runtime bundles and VM guests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestArch {
    X86_64,
    Aarch64,
}

impl GuestArch {
    /// Returns the canonical lowercase identifier for this architecture.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Returns the `GuestArch` matching the compiled host CPU architecture, if supported.
    pub const fn host_native() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Self::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(Self::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            None
        }
    }
}

impl fmt::Display for GuestArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for GuestArch {
    type Err = SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err(SandboxError::InvalidSpec(format!(
                "unsupported guest architecture '{s}'; expected 'x86_64' or 'aarch64'"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_arch_display_and_as_str() {
        assert_eq!(GuestArch::X86_64.as_str(), "x86_64");
        assert_eq!(GuestArch::Aarch64.as_str(), "aarch64");
        assert_eq!(GuestArch::X86_64.to_string(), "x86_64");
        assert_eq!(GuestArch::Aarch64.to_string(), "aarch64");
    }

    #[test]
    fn guest_arch_from_str_parses_known_and_rejects_unknown() {
        assert_eq!("x86_64".parse::<GuestArch>(), Ok(GuestArch::X86_64));
        assert_eq!("aarch64".parse::<GuestArch>(), Ok(GuestArch::Aarch64));

        for invalid in ["", "arm64", "amd64", "X86_64", " x86_64", "riscv64"] {
            assert!(
                matches!(invalid.parse::<GuestArch>(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for '{invalid}'"
            );
        }
    }

    #[test]
    fn guest_arch_host_native_matches_target() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(GuestArch::host_native(), Some(GuestArch::X86_64));
        #[cfg(target_arch = "aarch64")]
        assert_eq!(GuestArch::host_native(), Some(GuestArch::Aarch64));
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        assert_eq!(GuestArch::host_native(), None);
    }
}
