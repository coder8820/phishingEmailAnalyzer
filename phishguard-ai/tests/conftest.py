"""
Pytest global configuration and fixtures for PhishGuard AI.
Available to unit, integration, and security test suites.
"""
import os
import pytest
import pytest_asyncio
from types import SimpleNamespace
from uuid import UUID
from unittest.mock import MagicMock

# Set test environment flags
os.environ["APP_ENV"] = "test"
os.environ["APP_SECRET_KEY"] = "test-secret-key-64-character-hex-string-for-phishguard-pytest"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_phishguard.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["CELERY_BROKER_URL"] = "redis://localhost:6379/1"
os.environ["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/2"
os.environ["POSTGRES_PASSWORD"] = "testpass"
os.environ["AI_PROVIDER"] = "mock"
os.environ["TI_DEMO_MODE"] = "true"
os.environ["ENCRYPTION_KEY"] = "dGVzdC1lbmNyeXB0aW9uLWtleS1mb3ItdGVzdA=="
os.environ["TOKEN_ENCRYPTION_KEY"] = "k8F2j9pL4mN6qR8sT1uV3wX5yZ7aB9cD1eF3gH5iJ7k="
os.environ["GOOGLE_CLIENT_ID"] = "test-google-client-id.apps.googleusercontent.com"
os.environ["GOOGLE_CLIENT_SECRET"] = "test-google-client-secret"
os.environ["GOOGLE_REDIRECT_URI"] = "http://localhost:3001/integrations/gmail/callback"
os.environ["ALLOWED_ORIGINS"] = '["http://localhost:3001","http://localhost:3000","http://localhost:80"]'

from app.core.config import get_settings
get_settings.cache_clear()


@pytest.fixture(autouse=True)
def mock_celery_task(monkeypatch):
    """Prevent Celery from attempting real Redis connections during tests."""
    mock_delay = MagicMock(return_value=MagicMock(id="mock-task-id"))
    monkeypatch.setattr("app.workers.tasks.analyze_email_task.delay", mock_delay)
    return mock_delay


@pytest_asyncio.fixture(scope="function")
async def setup_test_database():
    """Ensure clean test tables and seed records for API tests."""
    from app.core.database import engine, Base, AsyncSessionLocal
    from app.models import Organization, User, Email, Incident, IOC
    from app.security.auth import hash_password

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Seed Organizations
        org_main = Organization(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            name="Main Org",
            slug="main-org",
            plan="enterprise",
            is_active=True,
        )
        org_a = Organization(
            id=UUID("00000000-0000-0000-0000-00000000000a"),
            name="Org A",
            slug="org-a",
            plan="enterprise",
            is_active=True,
        )
        org_b = Organization(
            id=UUID("00000000-0000-0000-0000-00000000000b"),
            name="Org B",
            slug="org-b",
            plan="enterprise",
            is_active=True,
        )
        session.add_all([org_main, org_a, org_b])

        # Seed Users
        u_analyst = User(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            organization_id=org_main.id,
            email="analyst@example.com",
            username="analyst",
            role="analyst",
            hashed_password=hash_password("Pass123!"),
            is_active=True,
        )
        u_admin = User(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            organization_id=org_main.id,
            email="admin@example.com",
            username="admin",
            role="security_admin",
            hashed_password=hash_password("Pass123!"),
            is_active=True,
        )
        u_viewer = User(
            id=UUID("00000000-0000-0000-0000-000000000004"),
            organization_id=org_main.id,
            email="viewer@example.com",
            username="viewer",
            role="viewer",
            hashed_password=hash_password("Pass123!"),
            is_active=True,
        )
        u_orga = User(
            id=UUID("00000000-0000-0000-0000-000000000005"),
            organization_id=org_a.id,
            email="orga@example.com",
            username="orga_user",
            role="analyst",
            hashed_password=hash_password("Pass123!"),
            is_active=True,
        )
        u_orgb = User(
            id=UUID("00000000-0000-0000-0000-000000000006"),
            organization_id=org_b.id,
            email="orgb@example.com",
            username="orgb_user",
            role="analyst",
            hashed_password=hash_password("Pass123!"),
            is_active=True,
        )
        u_test = User(
            id=UUID("00000000-0000-0000-0000-000000000007"),
            organization_id=org_main.id,
            email="testuser@phishguard.local",
            username="testuser",
            role="analyst",
            hashed_password=hash_password("ValidPassword123!"),
            is_active=True,
            failed_login_count=0,
        )
        session.add_all([u_analyst, u_admin, u_viewer, u_orga, u_orgb, u_test])

        # Cross-tenant Org B entities
        email_b = Email(
            id=UUID("00000000-0000-0000-0000-0000000000b1"),
            organization_id=org_b.id,
            submitted_by=u_orgb.id,
            source_type="eml_upload",
            original_filename="org_b.eml",
            analysis_status="queued",
        )
        incident_b = Incident(
            id=UUID("00000000-0000-0000-0000-0000000000b2"),
            organization_id=org_b.id,
            title="Org B Incident",
            severity="high",
            status="new",
            created_by=u_orgb.id,
        )
        session.add_all([email_b, incident_b])
        await session.flush()

        ioc_b = IOC(
            id=UUID("00000000-0000-0000-0000-0000000000b3"),
            organization_id=org_b.id,
            email_id=email_b.id,
            ioc_type="domain",
            ioc_value="evil-domain.com",
        )
        session.add(ioc_b)
        await session.commit()

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(setup_test_database):
    """Unauthenticated HTTP async client."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def authenticated_client(setup_test_database):
    """Authenticated HTTP client with analyst permissions."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.security.auth import create_access_token

    token = create_access_token(
        user_id="00000000-0000-0000-0000-000000000001",
        organization_id="00000000-0000-0000-0000-000000000002",
        role="analyst",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def analyst_client(authenticated_client):
    """Alias for analyst role client."""
    yield authenticated_client


@pytest_asyncio.fixture
async def admin_client(setup_test_database):
    """Authenticated HTTP client with security_admin permissions."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.security.auth import create_access_token

    token = create_access_token(
        user_id="00000000-0000-0000-0000-000000000003",
        organization_id="00000000-0000-0000-0000-000000000002",
        role="security_admin",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def viewer_client(setup_test_database):
    """Authenticated HTTP client with viewer permissions."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.security.auth import create_access_token

    token = create_access_token(
        user_id="00000000-0000-0000-0000-000000000004",
        organization_id="00000000-0000-0000-0000-000000000002",
        role="viewer",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def org_a_client(setup_test_database):
    """Authenticated HTTP client belonging to Organization A."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.security.auth import create_access_token

    token = create_access_token(
        user_id="00000000-0000-0000-0000-000000000005",
        organization_id="00000000-0000-0000-0000-00000000000a",
        role="analyst",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def org_b_client(setup_test_database):
    """Authenticated HTTP client belonging to Organization B."""
    from httpx import AsyncClient, ASGITransport
    from app.main import app
    from app.security.auth import create_access_token

    token = create_access_token(
        user_id="00000000-0000-0000-0000-000000000006",
        organization_id="00000000-0000-0000-0000-00000000000b",
        role="analyst",
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac


@pytest.fixture
def org_b_email_id():
    return "00000000-0000-0000-0000-0000000000b1"


@pytest.fixture
def org_b_incident_id():
    return "00000000-0000-0000-0000-0000000000b2"


@pytest.fixture
def org_b_ioc_id():
    return "00000000-0000-0000-0000-0000000000b3"


@pytest.fixture
def test_user():
    return SimpleNamespace(
        id="00000000-0000-0000-0000-000000000007",
        email="testuser@phishguard.local",
        username="testuser",
    )


@pytest_asyncio.fixture
async def db_session(setup_test_database):
    """Async database session fixture."""
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        yield session
