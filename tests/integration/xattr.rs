use crate::ext3::load_ext3;
use crate::test_util::load_test_disk1_rw;
use ext4plus::FollowSymlinks;
use ext4plus::path::Path;
use ext4plus::xattr::Xattrs;

#[maybe_async::test(
    feature = "sync",
    async(not(feature = "sync"), tokio::test)
)]
async fn test_load_blank_xattr() {
    let fs = load_ext3().await;

    let medium_dir = Path::new("/medium_dir");
    let inode = fs
        .path_to_inode(medium_dir, FollowSymlinks::All)
        .await
        .unwrap();
    let xattrs = Xattrs::from_inode(&inode, &fs).await.unwrap();
    assert!(xattrs.is_empty());
}

#[maybe_async::test(
    feature = "sync",
    async(not(feature = "sync"), tokio::test)
)]
async fn test_write_xattr() {
    let fs = load_test_disk1_rw().await;
    let mut inode = fs
        .path_to_inode(
            Path::try_from("/small_file").unwrap(),
            FollowSymlinks::All,
        )
        .await
        .unwrap();
    let mut xattrs = Xattrs::from_inode(&inode, &fs).await.unwrap();
    xattrs.insert(b"user.test".to_vec(), b"test value".to_vec());
    xattrs.write(&mut inode, &fs).await.unwrap();
    let xattrs = Xattrs::from_inode(&inode, &fs).await.unwrap();
    panic!("{xattrs:?}");
    assert_eq!(
        xattrs.get(&"user.test".as_bytes().to_vec()).unwrap(),
        b"test value"
    );
}
