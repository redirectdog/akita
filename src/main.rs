#[derive(Debug)]
enum Error {
    NoTasks,
    FailedToFetchTask(postgres::Error),
    ClientError(acme_client::error::Error),
    MissingChallenge,
    FailedToSaveChallenge(postgres::Error),
    CryptoError(acme_client::openssl::error::ErrorStack),
    FailedToSaveCert(postgres::Error),
}

fn main() {
    let db = postgres::Connection::connect(std::env::var("DATABASE_URL").expect("Missing DATABASE_URL"), postgres::TlsMode::None).expect("Failed to connect to database");

    let task_stmt = db.prepare("SELECT id, host FROM redirects WHERE allow_tls=TRUE AND acme_failed=FALSE AND tls_cert IS NULL LIMIT 1").expect("Failed to prepare statement");
    let update_challenge_stmt = db.prepare("UPDATE redirects SET acme_token=$1, acme_key_authorization=$2 WHERE id=$3").expect("Failed to prepare statement");
    let report_error_stmt = db.prepare("UPDATE redirects SET acme_failed=TRUE WHERE id=$1").expect("Failed to prepare statement");
    let update_cert_stmt = db.prepare("UPDATE redirects SET tls_privkey=$1, tls_cert=$2, tls_renewed_at=localtimestamp WHERE id=$3").expect("Failed to prepare statement");

    let (directory, intermediate_cert_url) = if std::env::var("USE_LE_STAGING").is_ok() {
        println!("Using LE staging");
        (
            acme_client::Directory::from_url("https://acme-staging.api.letsencrypt.org/directory"),
            "https://letsencrypt.org/certs/fakeleintermediatex1.pem",
        )
    } else {
        println!("Using LE");
        (
            acme_client::Directory::lets_encrypt(),
            acme_client::LETSENCRYPT_INTERMEDIATE_CERT_URL,
        )
    };
    let acme_account = directory
        .and_then(|directory| directory.account_registration().register())
        .expect("Failed to register with ACME");

    let intermediate_cert = reqwest::get(intermediate_cert_url)
        .and_then(|res| res.error_for_status())
        .map_err(|err| format!("Failed to request intermediate cert: {:?}", err))
        .and_then(|mut res| {
            use std::io::Read;

            let mut buf = Vec::new();
            res.read_to_end(&mut buf)
                .map_err(|err| format!("Failed to read intermediate cert: {:?}", err))?;

            Ok(buf)
        })
    .unwrap();

    loop {
        let result = task_stmt.query(&[])
            .map_err(Error::FailedToFetchTask)
            .and_then(|rows| {
                if rows.len() > 0 {
                    let row = rows.get(0);
                    let id: i32 = row.get(0);
                    let host: String = row.get(1);

                    println!("Got task: {}", host);

                    Ok((id, host))
                } else {
                    Err(Error::NoTasks)
                }
            })
        .and_then(|(id, host)| {
            acme_account.authorization(&host)
                .map_err(Error::ClientError)
                .and_then(|authorization| {
                    let challenge = authorization.get_http_challenge().ok_or(Error::MissingChallenge)?;
                    let token = challenge.token();
                    let key_authorization = challenge.key_authorization();

                    update_challenge_stmt.execute(&[&token, &key_authorization, &id])
                        .map_err(Error::FailedToSaveChallenge)
                        .and_then(|_| {
                            println!("validating...");
                            challenge.validate()
                                .map_err(Error::ClientError)
                        })
                })
            .and_then(|_| {
                acme_account.certificate_signer(&[&host])
                    .sign_certificate()
                    .map_err(Error::ClientError)
            })
            .and_then(|result| {
                let privkey = result.pkey().private_key_to_pem_pkcs8().map_err(Error::CryptoError)?;

                let mut cert = result.cert().to_pem().map_err(Error::CryptoError)?;
                cert.extend_from_slice(&intermediate_cert);

                update_cert_stmt.execute(&[&privkey, &cert, &id])
                    .map_err(Error::FailedToSaveCert)
            })
            .or_else(|err| {
                if let Err(err) = report_error_stmt.execute(&[&id]) {
                    eprintln!("Failed to report failure: {:?}", err);
                }

                Err(err)
            })
        });

        if let Err(err) = result {
            if let Error::NoTasks = err {
                std::thread::sleep(std::time::Duration::new(10, 0));
            } else {
                eprintln!("Error: {:?}", err);
                std::thread::sleep(std::time::Duration::new(5, 0));
            }
        }
    }
}
