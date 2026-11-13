"""
PhishGuard AI — Admin User Bootstrap Utility
Usage:
  python scripts/create_admin.py --email admin@phishguard.local --password "StrongPassword123!" --org "Primary SOC"
"""
import argparse
import asyncio
import os
import sys
import uuid

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import select

from app.core.database import AsyncSessionLocal, engine, Base
from app.models import Organization, User
from app.security.auth import hash_password


async def create_admin(email: str, password: str, org_name: str, username: str = "admin"):
    async with engine.begin() as conn:
        # Create schema if not exists
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Find or create organization
        res = await session.execute(select(Organization).where(Organization.name == org_name))
        org = res.scalar_one_or_none()
        if not org:
            org = Organization(
                name=org_name,
                slug=org_name.lower().replace(" ", "-"),
                plan="enterprise",
            )
            session.add(org)
            await session.flush()
            print(f"[+] Created organization: {org.name} ({org.id})")

        # Check existing user
        user_res = await session.execute(select(User).where(User.email == email))
        user = user_res.scalar_one_or_none()
        if user:
            print(f"[-] User with email {email} already exists.")
            return

        user = User(
            organization_id=org.id,
            email=email,
            username=username,
            display_name="SOC Super Administrator",
            hashed_password=hash_password(password),
            role="super_admin",
            is_active=True,
            is_email_verified=True,
        )
        session.add(user)
        await session.commit()
        print(f"[+] Successfully created Super Admin: {user.email} (ID: {user.id})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap Super Admin user")
    parser.add_argument("--email", default="admin@phishguard.local", help="Admin email")
    parser.add_argument("--password", default="AdminSecure2026!", help="Admin password")
    parser.add_argument("--org", default="Global Cyber Defense SOC", help="Organization name")
    parser.add_argument("--username", default="admin", help="Admin username")
    args = parser.parse_args()

    asyncio.run(create_admin(args.email, args.password, args.org, args.username))
