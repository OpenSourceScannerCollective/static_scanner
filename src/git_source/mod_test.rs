mod tests {
    use crate::git_source::GitRepo;
    const TEST_URL: &str = "https://github.com/OpenSourceScannerCollective/expired-creds.git";
    #[test]
    fn it_should_fetch_repo() {
        let Ok(mut repo) = GitRepo::remote(TEST_URL) else {
            assert!(false);
            return;
        };

        let Ok(_) = repo.flush() else {
            assert!(false);
            return;
        };
    }
}
