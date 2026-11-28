// A test must never read the developer's real identity. Agent seats export
// AWEB_IDENTITY_HOME, and config resolution honours it, so every test file
// starts without it; a test that needs one sets its own.
delete process.env.AWEB_IDENTITY_HOME;
