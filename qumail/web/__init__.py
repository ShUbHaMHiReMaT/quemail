"""The QuMail web inbox.

A small, self-contained HTTP application so that reading and sending encrypted
mail is a browser tab rather than a sequence of CLI invocations.

    auth     -- password hashing, sessions, CSRF, login throttling
    store    -- the merged view of sent and received messages
    pages    -- HTML rendering (everything interpolated is escaped)
    server   -- routing, security headers, and the background IMAP poller

Deliberately built on the standard library. This service holds a private key,
so every dependency added here is a dependency that could reach it.

SECURITY NOTE -- read before hosting this anywhere but localhost:

    Running the web inbox on a server means that server decrypts your mail and
    therefore holds your private key and its passphrase. The messages stay
    end-to-end encrypted with respect to your mail provider, the network, and
    anyone who is not the host -- but *not* with respect to whoever operates
    the machine it runs on. That is the same trade every webmail client makes.
    For a threat model where nobody but you may ever read the plaintext, run
    this on your own machine bound to 127.0.0.1.
"""
