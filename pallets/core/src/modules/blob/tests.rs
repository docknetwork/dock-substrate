use super::{did, Blob, BlobId, BlobOwner, Blobs, DispatchResult, Error};
use crate::{blob::AddBlob, common::Limits, did::Did, tests::common::*};
use sp_core::{sr25519, Pair};

fn create_blob(
    id: BlobId,
    content: Vec<u8>,
    author: BlobOwner,
    author_kp: sr25519::Pair,
    nonce: u64,
) -> Option<DispatchResult> {
    let bl = Blob {
        id,
        blob: content.clone().try_into().ok()?,
    };
    println!("did: {:?}", author);
    println!("pk: {:?}", author_kp.public().0);
    println!("id: {:?}", id);
    println!("content: {:?}", content);

    BlobMod::new(
        Origin::signed(ABBA),
        AddBlob {
            blob: bl.clone(),
            nonce,
        },
        did_sig::<Test, _, _>(&AddBlob { blob: bl, nonce }, &author_kp, author, 1),
    )
    .into()
}

fn get_max_blob_size() -> usize {
    <Test as Limits>::MaxBlobSize::get() as usize
}

#[test]
fn add_blob() {
    fn add(size: usize, block_no: u64) {
        run_to_block(block_no);

        let id: BlobId = rand::random();
        let noise = random_bytes(size);
        let (author, author_kp) = newdid();
        assert_eq!(Blobs::<Test>::get(id), None);
        create_blob(
            id,
            noise.clone(),
            BlobOwner(author),
            author_kp,
            block_no + 1,
        )
        .unwrap()
        .unwrap();
        // Can retrieve a valid blob and the blob contents and author match the given ones.
        assert_eq!(
            Blobs::<Test>::get(id),
            Some((BlobOwner(author), noise.try_into().unwrap()))
        );
        check_nonce(&author, block_no + 1);
    }

    ext().execute_with(|| {
        // Can add a blob with unique id, blob data of < MaxBlobSize bytes and a valid signature.
        add(get_max_blob_size() - 1, 10);
        add(get_max_blob_size() - 2, 20);
        add(0, 30);
        // Can add a blob with unique id, blob data of MaxBlobSize bytes and a valid signature.
        add(get_max_blob_size(), 40);
    });
}

#[test]
fn err_blob_too_big() {
    fn add_too_big(size: usize, block_no: u64) {
        run_to_block(block_no);

        let (author, author_kp) = newdid();
        let noise = random_bytes(size);
        let id = rand::random();
        assert_eq!(Blobs::<Test>::get(id), None);
        check_nonce(&author, block_no);
        assert!(create_blob(id, noise, BlobOwner(author), author_kp, block_no + 1).is_none());
        check_nonce(&author, block_no);
    }

    ext().execute_with(|| {
        add_too_big(get_max_blob_size() + 1, 10);
        add_too_big(get_max_blob_size() + 2, 20);
    });
}

#[test]
fn err_blob_already_exists() {
    ext().execute_with(|| {
        run_to_block(10);

        // Adding a blob with already used id fails with error BlobAlreadyExists.
        let id = rand::random();
        let (author, author_kp) = newdid();
        assert_eq!(Blobs::<Test>::get(id), None);
        check_nonce(&author, 10);
        create_blob(
            id,
            random_bytes(10),
            BlobOwner(author),
            author_kp.clone(),
            10 + 1,
        )
        .unwrap()
        .unwrap();
        check_nonce(&author, 10 + 1);
        let err = create_blob(id, random_bytes(10), BlobOwner(author), author_kp, 11 + 1)
            .unwrap()
            .unwrap_err();
        assert_eq!(err, Error::<Test>::BlobAlreadyExists.into());
        check_nonce(&author, 10 + 1);
    });
}

#[test]
fn err_did_does_not_exist() {
    ext().execute_with(|| {
        run_to_block(10);

        // Adding a blob with an unregistered DID fails with error DidDoesNotExist.
        let author = BlobOwner(Did(rand::random()));
        let author_kp = gen_kp();
        let err = create_blob(rand::random(), random_bytes(10), author, author_kp, 10 + 1)
            .unwrap()
            .unwrap_err();
        assert_eq!(err, did::Error::<Test>::NoKeyForDid.into());
    });
}

#[test]
fn err_invalid_sig() {
    ext().execute_with(|| {
        {
            run_to_block(10);
            // An invalid signature while adding a blob should fail with error InvalidSignature.
            let (author, author_kp) = newdid();
            let bl = Blob {
                id: rand::random(),
                blob: random_bytes(10).try_into().unwrap(),
            };
            let att = crate::attest::SetAttestationClaim::<Test> {
                attest: crate::attest::Attestation {
                    priority: 1,
                    iri: None,
                },
                nonce: 10 + 1,
            };
            check_nonce(&author, 10);
            let err = BlobMod::new(
                Origin::signed(ABBA),
                AddBlob {
                    blob: bl,
                    nonce: 10 + 1,
                },
                did_sig(&att, &author_kp, BlobOwner(author), 1),
            )
            .unwrap_err();
            assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
            check_nonce(&author, 10);
        }

        {
            run_to_block(20);

            // signature by other party
            let (author, _) = newdid();
            let (_, author_kp) = newdid();
            let bl = Blob {
                id: rand::random(),
                blob: random_bytes(10).try_into().unwrap(),
            };
            check_nonce(&author, 20);
            let err = BlobMod::new(
                Origin::signed(ABBA),
                AddBlob {
                    blob: bl.clone(),
                    nonce: 20 + 1,
                },
                did_sig::<Test, _, _>(
                    &AddBlob {
                        blob: bl,
                        nonce: 20 + 1,
                    },
                    &author_kp,
                    BlobOwner(author),
                    1,
                ),
            )
            .unwrap_err();
            assert_eq!(err, did::Error::<Test>::InvalidSignature.into());
            check_nonce(&author, 20);
        }
    })
}
