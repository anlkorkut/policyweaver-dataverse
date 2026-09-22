"""Local analyst console. Never expose this unauthenticated app on a network."""
from pathlib import Path
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .demo import demo_snapshot, example_queries
from .engine import AccessEngine
from .planner import plan
from .storage import load_inventory

STATIC = Path(__file__).with_name("static")


def inventory_summary(raw: dict | None) -> dict | None:
    if raw is None:
        return None
    return {key: raw.get(key) for key in (
        "organization_id", "environment_url", "observed_start", "observed_end", "complete",
        "counts", "diagnostics", "capabilities", "publication_ready", "publication_blockers")}


def create_app() -> FastAPI:
    app = FastAPI(title="PolicyWeaver local analysis", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])
    engine = AccessEngine(demo_snapshot())

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        if request.client and request.client.host not in ("127.0.0.1", "::1", "testclient"):
            return JSONResponse({"detail": "This analyst console accepts loopback clients only."}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        return response

    def current_inventory():
        try:
            return inventory_summary(load_inventory())
        except (OSError, ValueError, KeyError):
            return {"complete": False, "counts": {}, "diagnostics": [
                "Local inventory could not be verified; collect a fresh snapshot."], "publication_ready": False}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": "local_analysis", "production_enforcement": False}

    @app.get("/api/overview")
    def overview():
        return {
            "source_counts": [
                {"label": "Active user-name labels", "value": 14541, "source": "User-reported bank assignment inventory; pasted list says 14,545"},
                {"label": "Observed BU labels", "value": 93, "source": "Bank inventory labels; hierarchy unverified"},
                {"label": "Assigned role labels", "value": 293, "source": "Bank assignment inventory"},
                {"label": "Assignment rows", "value": 113921, "source": "User-reported source rows; 46,894 unique assignments"},
                {"label": "XML role GUIDs", "value": 159, "source": "194 exported role definitions; 34 duplicate-GUID groups"},
                {"label": "Read-labelled grants", "value": 19475, "source": "Existing validated workbook analysis; 60,991 all-action grants"},
            ],
            "inventory": current_inventory(),
            "deployment": {"status": "Blocked · analysis only", "blockers": [
                "Bank inventory and live demo environment are separate sources; resolve GUIDs and missing assignments.",
                "Collect and reconcile record sharing, hierarchy, Entra group membership, column masking, and data ownership.",
                "Select Fabric item and consuming engines; verify permission bypasses, quota, revocation latency, and parity.",
                "No production enforcement has been deployed; the simulator uses synthetic records.",
            ]},
            "capabilities": [
                {"name": "Multiple roles", "description": "Union scoped Read grants while retaining each role's BU anchor."},
                {"name": "Overlapping teams", "description": "Deduplicate membership, preserve team-only versus member Basic inheritance."},
                {"name": "Field profiles", "description": "Combine applicable column Read grants; row Read never bypasses column security."},
                {"name": "Publication gates", "description": "Inventory and analysis cannot activate Fabric permissions."},
            ],
            "plan": plan(engine),
        }

    @app.get("/api/inventory")
    def inventory():
        return current_inventory()

    @app.get("/api/demo")
    def demo():
        raw = engine.snapshot.model_dump(mode="json")
        raw["columns"] = [{"table": t.name, **c.model_dump()} for t in engine.snapshot.tables for c in t.columns]
        return {**raw, "example_queries": example_queries(), "policy_version": engine.version,
                "simulation": True}

    class Evaluation(BaseModel):
        model_config = ConfigDict(extra="forbid")
        user_id: str = Field(min_length=1, max_length=100)
        table: str = Field(min_length=1, max_length=100)
        record_id: str = Field(min_length=1, max_length=100)
        column: str | None = Field(default=None, max_length=100)

    @app.post("/api/evaluate")
    def evaluate(query: Evaluation):
        return engine.evaluate(**query.model_dump())

    @app.get("/")
    def index():
        return FileResponse(STATIC / "operations.html")

    @app.get("/analysis")
    def analysis():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/adapter/status")
    def adapter_status():
        from .config import load_config, state_path
        from .journal import Journal
        path = Path(os.environ.get("POLICYWEAVER_CONFIG", "policyweaver.config.json"))
        if not path.exists():
            return {"configured": False, "runs": [], "production_certified": False}
        try:
            config = load_config(path)
            journal = Journal(state_path(config, path))
            runs = journal.recent(20)
            active = journal.current()
            return {"configured": True, "deployment": config.deployment_name,
                    "environment": config.environment_url, "workspace_id": config.workspace_id,
                    "source_mode": "Dataverse authorized projections", "configured_readers": len(config.readers),
                    "discover_readers": config.discover_readers, "maximum_readers": config.max_readers,
                    "role_limit": config.role_limit, "reserved_roles": config.reserved_roles,
                    "tables": [{"name": t.name, "column_count": len(t.columns)} for t in config.tables],
                    "serving_items": config.serving_items, "refresh_seconds": config.refresh_interval_seconds,
                    "runs": runs, "active": active, "server_time": time.time(),
                    "production_certified": False, "native_expiry_self_enforcing": False}
        except Exception:
            return JSONResponse({"configured": False, "error": "Configuration or journal could not be verified.",
                                 "runs": [], "production_certified": False}, status_code=503)

    app.mount("/static", StaticFiles(directory=STATIC, check_dir=False), name="static")
    return app


app = create_app()
