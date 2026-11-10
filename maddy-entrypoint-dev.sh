#!/bin/sh
set -e

: "${MADDY_HOSTNAME:?MADDY_HOSTNAME is required}"
: "${MADDY_DOMAIN:?MADDY_DOMAIN is required}"
: "${MADDY_USER:?MADDY_USER is required}"
: "${MADDY_PASSWORD:?MADDY_PASSWORD is required}"

cat > /data/maddy.conf <<EOF
tls off
hostname ${MADDY_HOSTNAME}

\$(primary_domain) = ${MADDY_DOMAIN}
\$(local_domains) = \$(primary_domain)

auth.pass_table local_authdb {
    table sql_table {
        driver sqlite3
        dsn credentials.db
        table_name passwords
    }
}

storage.imapsql local_mailboxes {
    driver sqlite3
    dsn imapsql.db
}

target.smtp peer_delivery {
    targets tcp://maddy-peer:25
    starttls no
}
target.smtp phishing_delivery {
    targets tcp://maddy:25
    starttls no
}

smtp tcp://0.0.0.0:25 {
    limits {
        all rate 50 1s
    }
    destination \$(local_domains) {
        deliver_to &local_mailboxes
    }
    default_destination {
        reject 550 5.1.1 "User doesn't exist"
    }
}

submission tcp://0.0.0.0:587 {
    limits {
        all rate 50 1s
    }
    auth &local_authdb
    source \$(local_domains) {
        destination phishing.local {
            deliver_to &phishing_delivery
        }
        destination peer.test {
            deliver_to &peer_delivery
        }
        destination postmaster \$(local_domains) {
            deliver_to &local_mailboxes
        }
        default_destination {
            reject 550 5.1.1 "User doesn't exist"
        }
    }
    default_source {
        reject 501 5.1.8 "Non-local sender domain"
    }
}

imap tcp://0.0.0.0:143 {
    auth &local_authdb
    storage &local_mailboxes
}
EOF

echo "Ensuring user ${MADDY_USER} exists..."
printf '%s\n' "${MADDY_PASSWORD}" | maddy creds create "${MADDY_USER}" 2>&1 | grep -v -i "already exist" || true
maddy imap-acct create "${MADDY_USER}" 2>&1 | grep -v -i "already exist" || true

echo "Starting Maddy..."
exec maddy -config /data/maddy.conf run