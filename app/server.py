import os

import uvicorn


def main():
    uvicorn.run(
        app="app.main:app",
        host=os.getenv("CADDYMAN_HOST", "0.0.0.0"),
        port=int(os.getenv("CADDYMAN_PORT", "5052")),
        # Forwarded headers decide two things here: whether the session cookie is marked
        # Secure, and which address the login rate limit counts against. Trusting them from
        # anyone would let a client pick a new address per attempt, so only the listed
        # proxies are believed. Behind Caddy, set this to its address or the Docker subnet.
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("CADDYMAN_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )


if __name__ == "__main__":
    main()
