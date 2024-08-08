use crate::regex_detector::{Builder, Scanner};
use crate::lines::LinesEnds;

mod tests {
    use super::*;

    const GIVEN_TEST_DATA: &str = r#"
        [
          {
            "User name": "test-user-0",
            "Password": "'Qp+*'!ruZ89pyD"
          },
          {
            "User name": "test-user-1",
            "Password": "o*P2PX)79&kHsF0"
          },
          {
            "User name": "test-user-2",
            "Password": "KGX!0cpQdCr{K#I"
          },
          {
            "User name": "test-user-3",
            "Password": "7jEN3G[8Ts]e[{8"
          },
          {
            "User name": "test-user-4",
            "Password": "CPJZj|j(cP951A6"
          },
          {
            "User name": "test-user-5",
            "Password": "*=AAFegePCfrl12"
          },
          {
            "User name": "test-user-6",
            "Password": "MhPZx&GFqG7]b8v"
          },
          {
            "User name": "test-user-7",
            "Password": "X]pks}tZpj41sfJ"
          },
          {
            "User name": "test-user-8",
            "Password": "4jh3ew2-{w%(%2c"
          },
          {
            "User name": "test-user-9",
            "Password": "!4c)qvesGQnLXs|"
          }

my id -> 234231rfffasdfadf
password => asdfq340fade9023&#$@#@$

"some_id = 1234dkanamd"
some passowrd -> alsdkfjaksdj3293u4189389u


[
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
},
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
}
]
]"#;

const GIVEN_TEST_DATA_FALSE_POSITIVES: &str = r#"
    [
      {
        "User name": "test-user-0"
      },
      {
        "User name": "test-user-1"
      },
      {
        "User name": "test-user-2"
      },
      {
        "User name": "test-user-3"
      },
      {
        "User name": "test-user-4"
      },
      {
        "User name": "test-user-5"
      },
      {
        "User name": "test-user-6",
        "Password": "MhPZx&GFqG7]b8v"
      },
      {
        "User name": "test-user-7",
        "Password": "X]pks}tZpj41sfJ"
      },
      {
        "User name": "test-user-8",
        "Password": "4jh3ew2-{w%(%2c"
      },
      {
        "User name": "test-user-9",
        "Password": "!4c)qvesGQnLXs|"
      }

my id -> 234231rfffasdfadf
password => asdfq340fade9023&#$@#@$

"some_id = 1234dkanamd"
some passowrd -> alsdkfjaksdj3293u4189389u


[
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
},
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"private_key": "-----BEGIN PRIVATE KEY-----MIIBWwIBADCCATQGByqGSM44BAEwggEnAoGBAKUM1CBGwXTGv6j5PWTfcAkD5zp2fOQnT/bl9Be3y+c9yppoa9Z/WKv3Dc2rIg75hbjJcbgwFlLqpnJa7/a+g88UWzhZGHCRCtFMon3OFlw9xUzA3bh8VyzuMybG71eIt0TnJteFbc9bzHy742YQJkBUOmqkUkOcSUwd5AnXH8sxAh0Az+gTc64gel0LHg4k0a5Mi4xQomnMuC+Dy+pqBQKBgQCJc5Zsr2+CMUIF36EJI80+o7y76s+G4LUYu6+qnu5X/p5lK2mg2CqEHDQjkRMbBuAyVmIl/7uj14AUD4P4NJxptN4smzMLLu+dDyt1SzwZDPgDs6rTCKHkA18IDwazvpfr6RT1n8zZM8dbmWdXqDP5HNn4CQX6c/aFJe8dlwV3MAQeAhwPlZQFNUSYcSyX7jrv/WYvV1DyUMkYTmpVgmXA-----END PRIVATE KEY-----\n",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_x509_cert_url": ""
},
{
"type": "service_account",
"project_id": "",
"private_key_id": "",
"client_email": "",
"client_id": "",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://oauth2.googleapis.com/token",
"client_x509_cert_url": ""
}
]
]"#;

    #[test]
    fn it_should_create_scanner_and_find_all_secrets_gcp() {
        let lins_ends = LinesEnds::from_str(GIVEN_TEST_DATA);
        let Ok(scanner) = Builder::new()
            .with_name("GCP")
            .with_secret_regexes(&[r#"(-----BEGIN PUBLIC KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PUBLIC KEY-----)|(-----BEGIN PRIVATE KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PRIVATE KEY-----)|(-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+-=]+-----END PRIVATE KEY-----)"#])
            .with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#])
            .with_variables(&["private_key"], &[r#"(-----BEGIN PUBLIC KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PUBLIC KEY-----)|(-----BEGIN PRIVATE KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PRIVATE KEY-----)|(-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+-=]+-----END PRIVATE KEY-----)"#])
            .with_keys_required(&["auth_provider_x509_cert_url"])
            .try_build_scanner() else {
                assert!(false);
                return;
            };
        let Ok(results) = scanner.scan(GIVEN_TEST_DATA, "it_should_create_scanner_and_find_all_secrets_gcp", &lins_ends) else {
            assert!(false);
            return;
        };

        for result in results.iter() {
            assert!(result.raw_result.contains("-----BEGIN PRIVATE KEY----"));
            assert!(result.raw_result.contains("https://accounts.google.com/o/oauth2/auth"));
            assert!(result.raw_result.contains("https://oauth2.googleapis.com/token"));
            assert!(result.raw_result.contains("https://www.googleapis.com/oauth2/v1/certs"));
        }
    }

    #[test]
    fn it_should_create_scanner_and_find_only_full_covered_secrets_gcp() {
        let lins_ends = LinesEnds::from_str(GIVEN_TEST_DATA_FALSE_POSITIVES);
        let Ok(scanner) = Builder::new()
            .with_name("GCP")
            .with_secret_regexes(&[r#"(-----BEGIN PUBLIC KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PUBLIC KEY-----)|(-----BEGIN PRIVATE KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+/=]{1,63}(\n|\r|\r\n))?-----END PRIVATE KEY-----)|(-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+-=]+-----END PRIVATE KEY-----)"#])
            .with_variables(&["auth_uri", "token_uri","auth_provider_x509_cert_url"], &[r#"https://[a-zA-Z-0-9./]*"#])
            .with_variables(&["private_key"], &[r#"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+-=]+-----END PRIVATE KEY-----"#])
            .with_keys_required(&["auth_provider_x509_cert_url"])
            .try_build_scanner() else {
                assert!(false);
                return;
            };
        let Ok(results) = scanner.scan(GIVEN_TEST_DATA_FALSE_POSITIVES, "it_should_create_scanner_and_find_only_full_covered_secrets_gcp", &lins_ends) else {
            assert!(false);
            return;
        };


        for result in results.iter() {
            assert!(result.raw_result.contains("-----BEGIN PRIVATE KEY----"));
            assert!(result.raw_result.contains("https://accounts.google.com/o/oauth2/auth"));
            assert!(result.raw_result.contains("https://oauth2.googleapis.com/token"));
            assert!(result.raw_result.contains("https://www.googleapis.com/oauth2/v1/certs"));
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn it_should_create_scanner_and_find_only_full_covered_secrets_aws() {
        let lins_ends = LinesEnds::from_str(GIVEN_TEST_DATA_FALSE_POSITIVES);
        let Ok(scanner) = Builder::new()
            .with_name("AWS")
            .with_variables(&["User name"], &[r#"[a-zA-Z-0-9]+"#])
            .with_variables(&["Password"], &[r#"[\w\-%\(\)\{\}\]\[]+"#])
            .with_keys_required(&["User name", "Password"])
            .try_build_scanner() else {
                assert!(false);
                return;
            };
        let Ok(results) = scanner.scan(GIVEN_TEST_DATA_FALSE_POSITIVES, "it_should_create_scanner_and_find_only_full_covered_secrets_aws", &lins_ends) else {
            assert!(false);
            return;
        };


        for result in results.iter() {
            assert!(result.raw_result.contains("User name"));
            assert!(result.raw_result.contains("Password"));
        }
        assert_eq!(results.len(), 4);
    }
}
