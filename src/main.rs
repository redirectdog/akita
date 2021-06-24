#[derive(Debug)]
enum Error {
    NoTasks,
    FailedToFetchTask(postgres::Error),
    Client(acme_micro::Error),
    MissingChallenge,
    FailedToSaveChallenge(postgres::Error),
    FailedToSaveCert(postgres::Error),
    ValidationLost,
}

fn main() {
    let contact_email = std::env::var("CONTACT_EMAIL").expect("Missing CONTACT_EMAIL");

    let db = postgres::Connection::connect(
        std::env::var("DATABASE_URL").expect("Missing DATABASE_URL"),
        postgres::TlsMode::None,
    )
    .expect("Failed to connect to database");

    let task_stmt = db.prepare("SELECT id, host FROM redirects WHERE record_confirmed=TRUE AND acme_failed=FALSE AND (tls_cert IS NULL OR tls_renewed_at + INTERVAL '2 MONTHS' < localtimestamp) LIMIT 1").expect("Failed to prepare statement");
    let update_challenge_stmt = db
        .prepare("UPDATE redirects SET acme_token=$1, acme_key_authorization=$2 WHERE id=$3")
        .expect("Failed to prepare statement");
    let report_error_stmt = db
        .prepare("UPDATE redirects SET acme_failed=TRUE WHERE id=$1")
        .expect("Failed to prepare statement");
    let update_cert_stmt = db.prepare("UPDATE redirects SET tls_privkey=$1, tls_cert=$2, tls_renewed_at=localtimestamp WHERE id=$3").expect("Failed to prepare statement");

    let (directory,) = if std::env::var("USE_LE_STAGING").is_ok() {
        println!("Using LE staging");
        (acme_micro::Directory::from_url(
            acme_micro::DirectoryUrl::LetsEncryptStaging,
        ),)
    } else {
        println!("Using LE");
        (acme_micro::Directory::from_url(
            acme_micro::DirectoryUrl::LetsEncrypt,
        ),)
    };
    let acme_account = directory
        .and_then(|directory| directory.register_account(vec![format!("mailto:{}", contact_email)]))
        .expect("Failed to register with ACME");

    loop {
        let result = task_stmt
            .query(&[])
            .map_err(Error::FailedToFetchTask)
            .and_then(|rows| {
                if !rows.is_empty() {
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
                acme_account
                    .new_order(&host, &[])
                    .map_err(Error::Client)
                    .and_then(|mut order| {
                        let challenge = order
                            .authorizations()
                            .map_err(Error::Client)?
                            .first()
                            .and_then(|auth| auth.http_challenge())
                            .ok_or(Error::MissingChallenge)?;
                        let token = challenge.http_token();
                        let key_authorization = challenge.http_proof().map_err(Error::Client)?;

                        update_challenge_stmt
                            .execute(&[&token, &key_authorization, &id])
                            .map_err(Error::FailedToSaveChallenge)
                            .and_then(|_| {
                                println!("validating...");
                                challenge
                                    .validate(std::time::Duration::from_secs(10))
                                    .map_err(Error::Client)?;

                                order.refresh().map_err(Error::Client)?;
                                order.confirm_validations().ok_or(Error::ValidationLost)
                            })
                    })
                    .and_then(|csr_order| {
                        csr_order
                            .finalize_pkey(
                                acme_micro::create_p384_key().map_err(Error::Client)?,
                                std::time::Duration::from_secs(60),
                            )
                            .map_err(Error::Client)
                    })
                    .and_then(|cert_order| cert_order.download_cert().map_err(Error::Client))
                    .and_then(|result| {
                        let privkey = result.private_key().as_bytes();

                        let cert = result.certificate().as_bytes();

                        update_cert_stmt
                            .execute(&[&privkey, &cert, &id])
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
