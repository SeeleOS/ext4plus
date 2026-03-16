//! Extended attributes.

use crate::Ext4;
use crate::error::{CorruptKind, Ext4Error};
use crate::features::CompatibleFeatures;
use crate::inode::Inode;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

const MAGIC: u32 = 0xEA020000;

const PREFIX_0: &[u8] = b"";
const PREFIX_1: &[u8] = b"user.";
const PREFIX_2: &[u8] = b"system.posix_acl_access.";
const PREFIX_3: &[u8] = b"system.posix_acl_default.";
const PREFIX_4: &[u8] = b"trusted.";
const PREFIX_6: &[u8] = b"security.";
const PREFIX_7: &[u8] = b"system.";
const PREFIX_8: &[u8] = b"system.rich_acl";

const INLINE_PREFIXES: [&[u8]; 7] = [
    PREFIX_0, PREFIX_1, PREFIX_2, PREFIX_3, PREFIX_4, PREFIX_6, PREFIX_7,
];

const BLOCK_PREFIXES: [&[u8]; 6] =
    [PREFIX_0, PREFIX_1, PREFIX_2, PREFIX_3, PREFIX_4, PREFIX_6];

const ALL_PREFIXES: [&[u8]; 8] = [
    PREFIX_0, PREFIX_1, PREFIX_2, PREFIX_3, PREFIX_4, PREFIX_6, PREFIX_7,
    PREFIX_8,
];

fn shorten(s: &[u8], in_block: bool) -> (u8, &[u8]) {
    let prefixes: &[&[u8]] = if in_block {
        &BLOCK_PREFIXES
    } else {
        &INLINE_PREFIXES
    };
    for (i, prefix) in prefixes.iter().skip(1).enumerate() {
        if s.starts_with(prefix) {
            return (i as u8, &s[prefix.len()..]);
        }
    }
    (0, s)
}

// TODO: Cow this
fn restore_prefix(index: u8, name: &[u8]) -> Result<Vec<u8>, ()> {
    if index == 0 {
        return Ok(name.to_vec());
    }
    if let Some(prefix) = ALL_PREFIXES.get(index as usize) {
        let mut full_name = prefix.to_vec();
        full_name.extend_from_slice(name);
        return Ok(full_name);
    }
    Err(())
}

pub(crate) enum XattrSource {
    Inode(Vec<u8>),
    #[expect(unused)]
    Block(Vec<u8>),
}

pub(crate) struct XattrHeader {
    refcount: u32,
    #[expect(unused)]
    blocks: u32,
    #[expect(unused)]
    hash: u32,
    #[expect(unused)]
    checksum: u32,
}

impl XattrHeader {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Ext4Error> {
        if bytes.len() < 0x18 {
            return Err(CorruptKind::XattrHeader)?;
        }

        let magic = u32::from_le_bytes(bytes[0x0..0x4].try_into().unwrap());
        if magic != MAGIC {
            return Err(CorruptKind::XattrHeader)?;
        }
        if bytes[0x14..0x18] != [0; 4] {
            return Err(CorruptKind::XattrHeader)?;
        }

        // OK to unwrap: we already checked the length.
        Ok(Self {
            refcount: u32::from_le_bytes(bytes[0x4..0x8].try_into().unwrap()),
            blocks: u32::from_le_bytes(bytes[0x8..0xC].try_into().unwrap()),
            hash: u32::from_le_bytes(bytes[0xC..0x10].try_into().unwrap()),
            checksum: u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap()),
        })
    }
}

pub(crate) struct XattrEntry {
    index: u8,
    value_offset: u16,
    value_inum: u32,
    value_size: u32,
    hash: u32,
    name: Vec<u8>,
}

impl XattrEntry {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Ext4Error> {
        if bytes.len() < 0x18 {
            return Err(CorruptKind::XattrEntry)?;
        }
        let name_len = bytes[0] as usize;
        if bytes.len() < 0x18 + name_len {
            return Err(CorruptKind::XattrEntry)?;
        }
        Ok(Self {
            index: bytes[0],
            value_offset: u16::from_le_bytes(
                bytes[0x1..0x3].try_into().unwrap(),
            ),
            value_inum: u32::from_le_bytes(bytes[0x3..0x7].try_into().unwrap()),
            value_size: u32::from_le_bytes(bytes[0x7..0xB].try_into().unwrap()),
            hash: u32::from_le_bytes(bytes[0xB..0xF].try_into().unwrap()),
            name: bytes[0xF..0xF + name_len].to_vec(),
        })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; 0x18 + self.name.len()];
        bytes[0] = u8::try_from(self.name.len()).unwrap();
        bytes[0x1..0x2].copy_from_slice(&self.index.to_le_bytes());
        bytes[0x2..0x4].copy_from_slice(&self.value_offset.to_le_bytes());
        bytes[0x4..0x8].copy_from_slice(&self.value_inum.to_le_bytes());
        bytes[0x8..0xC].copy_from_slice(&self.value_size.to_le_bytes());
        bytes[0xC..0x10].copy_from_slice(&self.hash.to_le_bytes());
        bytes[0x10..0x10 + self.name.len()]
            .copy_from_slice(self.name.as_slice());
        bytes
    }
}

/// Xattr list of an inode.
#[derive(Debug)]
pub struct Xattrs {
    #[expect(unused)]
    refcount: u32,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Deref for Xattrs {
    type Target = BTreeMap<Vec<u8>, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl DerefMut for Xattrs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

impl Xattrs {
    /// Load the xattrs from the inode and/or blocks.
    pub async fn from_inode(
        inode: &Inode,
        ext4: &Ext4,
    ) -> Result<Self, Ext4Error> {
        if !ext4
            .0
            .superblock
            .compatible_features()
            .contains(CompatibleFeatures::EXT_ATTR)
        {
            return Err(Ext4Error::NotSupported)?;
        }
        if inode.xattr_location() != 0 {
            let mut block = vec![0; ext4.0.superblock.block_size().to_usize()];
            ext4.read_from_block(inode.xattr_location(), 0, &mut block)
                .await?;
            let header = XattrHeader::from_bytes(&block)?;
            let data = &block[0x18..];
            let mut entries = BTreeMap::default();
            let mut pointer = 0;
            while pointer < data.len() {
                let name_len = usize::from(data[pointer]);
                if name_len == 0 {
                    break;
                }
                let entry_bytes = &data[pointer..pointer + 0x18 + name_len];
                let entry = XattrEntry::from_bytes(entry_bytes).unwrap();
                entries.insert(
                    restore_prefix(entry.index, &entry.name).unwrap(),
                    data[entry.value_offset as usize
                        ..entry.value_offset as usize
                            + entry.value_size as usize]
                        .to_vec(),
                );
                pointer += 0x18 + name_len;
            }
            return Ok(Self {
                refcount: header.refcount,
                entries,
            });
        }
        let inline_xattr = inode.inline_xattr();
        if inline_xattr[0..4] != MAGIC.to_le_bytes() {
            return Ok(Self {
                refcount: 0,
                entries: BTreeMap::default(),
            });
        }
        let inline_xattr = &inline_xattr[4..];
        let mut entries = BTreeMap::default();
        let mut pointer = 0x0;
        while pointer < inline_xattr.len() {
            let name_len = usize::from(inline_xattr[pointer]);
            if name_len == 0 {
                break;
            }
            let entry_bytes = &inline_xattr[pointer..pointer + 0x18 + name_len];
            let entry = XattrEntry::from_bytes(entry_bytes)?;
            entries.insert(
                restore_prefix(entry.index, &entry.name).unwrap(),
                inline_xattr[entry.value_offset as usize
                    ..entry.value_offset as usize + entry.value_size as usize]
                    .to_vec(),
            );
            pointer += 0x11 + name_len;
        }
        Ok(Self {
            refcount: 0,
            entries,
        })
    }

    fn can_inline(&self, inline_space: u16) -> bool {
        let mut space = 4;
        for entry in &self.entries {
            space += 0x16
                + shorten(&entry.0, false).1.len() as u16
                + entry.1.len() as u16;
        }
        space <= inline_space
    }

    pub(crate) fn to_bytes(
        &self,
        inline_space: u16,
        ext4: &Ext4,
    ) -> Result<XattrSource, Ext4Error> {
        let can_inline = self.can_inline(inline_space);
        let mut entry_pointer = if can_inline { 0x0 } else { 0x18 };
        let mut value_pointer = if can_inline {
            (inline_space - 4) - (inline_space % 4)
        } else {
            ext4.0.superblock.block_size().to_u32() as u16
        };
        let mut entries = Vec::new();
        let mut values = Vec::new();
        for entry in &self.entries {
            value_pointer -= entry.1.len() as u16;
            value_pointer -= value_pointer % 4; // Align to 4 bytes.
            values.push((value_pointer, entry.1.clone()));
            let (index, name) = shorten(&entry.0, !can_inline);
            let hash = if can_inline {
                0
            } else {
                todo!();
            };
            entries.push(XattrEntry {
                index,
                value_offset: value_pointer,
                value_inum: 0,
                value_size: entry.1.len() as u32,
                hash,
                name: name.to_vec(),
            });
            entry_pointer += 0x18 + name.len() as u16;
            if entry_pointer > value_pointer {
                return Err(Ext4Error::NoSpace);
            }
        }
        if can_inline {
            let mut bytes = vec![0; usize::from(inline_space)];
            bytes[0x0..0x4].copy_from_slice(MAGIC.to_le_bytes().as_slice());
            let mut pointer = 0x4u16;
            for entry in &entries {
                let entry_bytes = entry.to_bytes();
                bytes[usize::from(pointer)
                    ..(usize::from(pointer) + entry_bytes.len())]
                    .copy_from_slice(entry_bytes.as_slice());
                pointer = pointer
                    .checked_add(u16::try_from(entry_bytes.len()).unwrap())
                    .unwrap();
            }
            for (offset, value) in values {
                bytes[usize::from(offset)
                    ..usize::from(offset).checked_add(value.len()).unwrap()]
                    .copy_from_slice(value.as_slice());
            }
            Ok(XattrSource::Inode(bytes))
        } else {
            todo!();
        }
    }

    /// Write the xattrs to the inode and/or blocks.
    pub async fn write(
        &self,
        inode: &mut Inode,
        ext4: &Ext4,
    ) -> Result<(), Ext4Error> {
        let source = self.to_bytes(inode.inline_xattr_space(), ext4)?;
        match source {
            XattrSource::Inode(bytes) => {
                if inode.xattr_location() != 0 {
                    ext4.free_block(inode.xattr_location()).await?;
                    inode.set_xattr_location(0);
                }
                inode.set_inline_xattr(&bytes);
                inode.write(ext4).await?;
                Ok(())
            }
            XattrSource::Block(_bytes) => {
                todo!();
            }
        }
    }
}
