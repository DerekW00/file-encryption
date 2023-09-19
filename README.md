# A Secure File Sharing System

This project involves designing and implementing the client application for a secure file-sharing system, akin to Dropbox but encrypted to prevent the server from viewing or tampering with the data. The application will be written in Golang and will provide several functionalities to the users such as file saving, loading, overwriting, appending, sharing, and revocation of shared files.

The project outline details several design requirements, including user authentication, user session handling, cryptographic keys usage, file sharing, and revocation protocols, as well as input-output efficiency. The design will need to consider two types of potential adversaries: the datastore adversary who can modify the data stored in the datastore and the revoked user adversary, who may try to perform operations on arbitrary files once their access is revoked.

Some key design requirements include:
- Usernames and passwords: The application must handle unique, case-sensitive usernames and non-unique passwords, and support username and password lengths greater than zero.
- User sessions: The client application must support multiple users using the application concurrently and a single user having multiple active sessions.
- Cryptography and keys: Each public key should be used for a single purpose, with each user likely having multiple public keys. The application should avoid reusing the same key for multiple purposes and the patterns like authenticate-then-encrypt or decrypt-then-verify.
- Files: The client must ensure confidentiality and integrity of file contents, file sharing invitations, and file names. The client must also prevent adversaries from learning filenames and file lengths.
- Sharing and revocation: The client must enforce authorization for all files and allow any authorized user to read, overwrite, and append to the file, and share it with other users.
- I/O efficiency: The client must allow users to efficiently append new content to previously stored files, measured in terms of bandwidth usage.
- Golang-specific requirements: The application must not use global variables (except for basic constants), and Go functions must return an error if malicious actions prevent them from functioning properly.

The resources provided for the project include two servers (Keystore and Datastore), cryptographic algorithm implementations, and starter code with eight API functions to be implemented. The project provides a detailed threat model and design requirements to be met. The application's design must comply with these requirements to ensure a high degree of security and functionality.
