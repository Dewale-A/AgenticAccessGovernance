"""
IAM Database Module - SQLite database with JSON seed data loading.
Handles all database operations for the access governance system.
"""

import json
import sqlite3
import logging
import asyncio
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

import aiosqlite
from src.config.settings import settings

logger = logging.getLogger(__name__)


class IAMDatabase:
    """
    SQLite database manager for IAM governance data.
    Loads initial data from JSON files and provides async database operations.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to SQLite database file (defaults to settings)
        """
        if db_path:
            self.db_path = db_path
        else:
            # Extract path from database URL (remove sqlite:/// prefix)
            db_url = settings.database_url
            if db_url.startswith("sqlite:///"):
                self.db_path = db_url[10:]  # Remove "sqlite:///" prefix
            else:
                self.db_path = "data/agentic_iam.db"
        
        # Ensure database directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.data_dir = Path("data")
        self._initialized = False
    
    async def initialize(self):
        """Initialize the database and load seed data."""
        if self._initialized:
            return
        
        try:
            logger.info(f"Initializing database at {self.db_path}")
            
            # Create tables
            await self._create_tables()
            
            # Check if data already exists
            if not await self._has_seed_data():
                # Load seed data from JSON files
                await self._load_seed_data()
                logger.info("Seed data loaded successfully")
            else:
                logger.info("Database already contains data, skipping seed load")
            
            self._initialized = True
            logger.info("Database initialization complete")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise
    
    async def _create_tables(self):
        """Create all necessary database tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Users table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    department TEXT NOT NULL,
                    role TEXT NOT NULL,
                    title TEXT NOT NULL,
                    hire_date TEXT NOT NULL,
                    last_certification_date TEXT,
                    manager_id TEXT,
                    status TEXT DEFAULT 'active',
                    privacy_training_date TEXT,
                    model_risk_training_date TEXT,
                    background_check_date TEXT,
                    sox_certification_date TEXT,
                    risk_score INTEGER DEFAULT 50,
                    failed_access_attempts INTEGER DEFAULT 0,
                    last_login TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Systems table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS systems (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    sensitivity_tier TEXT NOT NULL,
                    data_classification TEXT,
                    regulator TEXT,
                    owner_department TEXT NOT NULL,
                    data_sensitivity_score INTEGER DEFAULT 50,
                    regulatory_impact TEXT DEFAULT 'MEDIUM',
                    audit_required BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Policies table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    description TEXT,
                    conditions TEXT, -- JSON
                    action TEXT NOT NULL,
                    priority INTEGER DEFAULT 100,
                    created_date TEXT NOT NULL,
                    last_modified TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    regulatory_reference TEXT
                )
            """)
            
            # RBAC Rules table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS rbac_rules (
                    id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    system TEXT NOT NULL,
                    access_levels TEXT, -- JSON array
                    conditions TEXT, -- JSON
                    exceptions TEXT -- JSON array
                )
            """)
            
            # SoD Rules table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sod_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    conflicting_systems TEXT, -- JSON array
                    conflicting_roles TEXT, -- JSON array
                    severity TEXT DEFAULT 'HIGH',
                    exceptions_allowed BOOLEAN DEFAULT 0,
                    exception_conditions TEXT -- JSON array
                )
            """)
            
            # Regulatory Constraints table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS regulatory_constraints (
                    id TEXT PRIMARY KEY,
                    regulator TEXT NOT NULL,
                    regulation_name TEXT NOT NULL,
                    description TEXT,
                    applies_to_systems TEXT, -- JSON array
                    applies_to_roles TEXT, -- JSON array
                    certification_required TEXT,
                    certification_validity_days INTEGER,
                    is_mandatory BOOLEAN DEFAULT 1,
                    violation_severity TEXT DEFAULT 'HIGH',
                    audit_frequency TEXT
                )
            """)
            
            # Entitlements table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS entitlements (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    access_level TEXT NOT NULL,
                    granted_date TEXT NOT NULL,
                    granted_by TEXT NOT NULL,
                    expires_date TEXT,
                    last_used TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (system_id) REFERENCES systems (id)
                )
            """)
            
            # Access Requests table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS access_requests (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    access_level TEXT NOT NULL,
                    request_type TEXT DEFAULT 'new_access',
                    justification TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    requested_date TEXT NOT NULL,
                    required_by_date TEXT,
                    is_emergency BOOLEAN DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    risk_score INTEGER,
                    risk_level TEXT,
                    approved_by TEXT,
                    approved_date TEXT,
                    denied_by TEXT,
                    denied_date TEXT,
                    denial_reason TEXT,
                    temporary_until TEXT,
                    decision_history TEXT, -- JSON
                    policy_violations TEXT, -- JSON array
                    regulatory_flags TEXT, -- JSON array
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (system_id) REFERENCES systems (id)
                )
            """)
            
            # Audit Records table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    confidence_score REAL,
                    policies_evaluated TEXT, -- JSON array
                    risk_factors TEXT, -- JSON array
                    regulatory_considerations TEXT, -- JSON array
                    metadata TEXT, -- JSON
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Governance Decisions table (for storing crew results)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS governance_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL UNIQUE,
                    final_decision TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    workflow_version TEXT,
                    reasoning TEXT,
                    risk_analysis TEXT, -- JSON
                    policy_analysis TEXT, -- JSON
                    certification_analysis TEXT, -- JSON
                    audit_trail TEXT, -- JSON
                    full_result TEXT, -- JSON of complete crew result
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_users_department ON users(department)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_entitlements_user_id ON entitlements(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_entitlements_system_id ON entitlements(system_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_access_requests_user_id ON access_requests(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_records_request_id ON audit_records(request_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_governance_decisions_request_id ON governance_decisions(request_id)")
            
            await db.commit()
            logger.info("Database tables created successfully")
    
    async def _has_seed_data(self) -> bool:
        """Check if database already contains seed data."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM users")
            row = await cursor.fetchone()
            return row[0] > 0 if row else False
    
    async def _load_seed_data(self):
        """Load seed data from JSON files."""
        logger.info("Loading seed data from JSON files")
        
        # Load users
        await self._load_users()
        
        # Load systems
        await self._load_systems()
        
        # Load policies
        await self._load_policies()
        
        # Load entitlements
        await self._load_entitlements()
        
        # Load sample requests (if they exist)
        await self._load_sample_requests()
    
    async def _load_users(self):
        """Load users from JSON file."""
        users_file = self.data_dir / "users.json"
        if not users_file.exists():
            logger.warning(f"Users file not found at {users_file}")
            return
        
        with open(users_file, 'r') as f:
            users_data = json.load(f)
        
        # Handle both list and dict formats
        users_list = users_data if isinstance(users_data, list) else users_data.get("users", [])
        
        async with aiosqlite.connect(self.db_path) as db:
            for user in users_list:
                await db.execute("""
                    INSERT OR REPLACE INTO users (
                        id, name, email, department, role, title, hire_date,
                        last_certification_date, manager_id, status,
                        privacy_training_date, model_risk_training_date,
                        background_check_date, sox_certification_date,
                        risk_score, failed_access_attempts, last_login
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user["id"], user["name"], user["email"], user["department"],
                    user["role"], user["title"], user["hire_date"],
                    user.get("last_certification_date"), user.get("manager_id"),
                    user.get("status", "active"),
                    user.get("privacy_training_date"), user.get("model_risk_training_date"),
                    user.get("background_check_date"), user.get("sox_certification_date"),
                    user.get("risk_score", 50), user.get("failed_access_attempts", 0),
                    user.get("last_login")
                ))
            await db.commit()
            logger.info(f"Loaded {len(users_list)} users")
    
    async def _load_systems(self):
        """Load systems from JSON file."""
        systems_file = self.data_dir / "systems.json"
        if not systems_file.exists():
            logger.warning(f"Systems file not found at {systems_file}")
            return
        
        with open(systems_file, 'r') as f:
            systems_data = json.load(f)
        
        # Handle both list and dict formats
        systems_list = systems_data if isinstance(systems_data, list) else systems_data.get("systems", [])
        
        async with aiosqlite.connect(self.db_path) as db:
            for system in systems_list:
                await db.execute("""
                    INSERT OR REPLACE INTO systems (
                        id, name, description, sensitivity_tier, data_classification,
                        regulator, owner_department, data_sensitivity_score,
                        regulatory_impact, audit_required
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    system["id"], system["name"], system["description"],
                    system["sensitivity_tier"], system["data_classification"],
                    system.get("regulator"), system["owner_department"],
                    system.get("data_sensitivity_score", 50),
                    system.get("regulatory_impact", "MEDIUM"),
                    system.get("audit_required", True)
                ))
            await db.commit()
            logger.info(f"Loaded {len(systems_list)} systems")
    
    async def _load_policies(self):
        """Load policies from JSON file."""
        policies_file = self.data_dir / "policies.json"
        if not policies_file.exists():
            logger.warning(f"Policies file not found at {policies_file}")
            return
        
        with open(policies_file, 'r') as f:
            policies_data = json.load(f)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Load RBAC rules
            for rule in policies_data.get("rbac_rules", []):
                await db.execute("""
                    INSERT OR REPLACE INTO rbac_rules (
                        id, role, system, access_levels, conditions, exceptions
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rule["id"], rule["role"], rule["system"],
                    json.dumps(rule["access_levels"]),
                    json.dumps(rule.get("conditions", {})),
                    json.dumps(rule.get("exceptions", []))
                ))
            
            # Load SoD rules
            for rule in policies_data.get("sod_rules", []):
                await db.execute("""
                    INSERT OR REPLACE INTO sod_rules (
                        id, name, description, conflicting_systems, conflicting_roles,
                        severity, exceptions_allowed, exception_conditions
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule["id"], rule["name"], rule["description"],
                    json.dumps(rule["conflicting_systems"]),
                    json.dumps(rule.get("conflicting_roles", [])),
                    rule.get("severity", "HIGH"),
                    rule.get("exceptions_allowed", False),
                    json.dumps(rule.get("exception_conditions", []))
                ))
            
            # Load regulatory constraints
            for constraint in policies_data.get("regulatory_constraints", []):
                await db.execute("""
                    INSERT OR REPLACE INTO regulatory_constraints (
                        id, regulator, regulation_name, description, applies_to_systems,
                        applies_to_roles, certification_required, certification_validity_days,
                        is_mandatory, violation_severity, audit_frequency
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    constraint["id"], constraint["regulator"], constraint["regulation_name"],
                    constraint["description"], json.dumps(constraint["applies_to_systems"]),
                    json.dumps(constraint.get("applies_to_roles", [])),
                    constraint.get("certification_required"),
                    constraint.get("certification_validity_days"),
                    constraint.get("is_mandatory", True),
                    constraint.get("violation_severity", "HIGH"),
                    constraint.get("audit_frequency")
                ))
            
            await db.commit()
            logger.info("Loaded policies, RBAC rules, SoD rules, and regulatory constraints")
    
    async def _load_entitlements(self):
        """Load entitlements from JSON file."""
        entitlements_file = self.data_dir / "entitlements.json"
        if not entitlements_file.exists():
            logger.warning(f"Entitlements file not found at {entitlements_file}")
            return
        
        with open(entitlements_file, 'r') as f:
            entitlements_data = json.load(f)
        
        # Handle both list and dict formats
        entitlements_list = entitlements_data if isinstance(entitlements_data, list) else entitlements_data.get("entitlements", [])
        
        async with aiosqlite.connect(self.db_path) as db:
            for entitlement in entitlements_list:
                await db.execute("""
                    INSERT OR REPLACE INTO entitlements (
                        id, user_id, system_id, access_level, granted_date,
                        granted_by, expires_date, last_used, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entitlement["id"], entitlement["user_id"], entitlement["system_id"],
                    entitlement["access_level"], entitlement["granted_date"],
                    entitlement["granted_by"], entitlement.get("expires_date"),
                    entitlement.get("last_used"), entitlement.get("is_active", True)
                ))
            await db.commit()
            logger.info(f"Loaded {len(entitlements_list)} entitlements")
    
    async def _load_sample_requests(self):
        """Load sample access requests from JSON files."""
        requests_dir = self.data_dir / "requests"
        if not requests_dir.exists():
            return
        
        async with aiosqlite.connect(self.db_path) as db:
            count = 0
            for request_file in requests_dir.glob("*.json"):
                with open(request_file, 'r') as f:
                    request_data = json.load(f)
                
                await db.execute("""
                    INSERT OR REPLACE INTO access_requests (
                        id, user_id, system_id, access_level, request_type,
                        justification, requested_by, requested_date,
                        required_by_date, is_emergency, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    request_data["id"], request_data["user_id"], request_data["system_id"],
                    request_data["access_level"], request_data.get("request_type", "new_access"),
                    request_data["justification"], request_data["requested_by"],
                    request_data["requested_date"], request_data.get("required_by_date"),
                    request_data.get("is_emergency", False), request_data.get("status", "pending")
                ))
                count += 1
            
            await db.commit()
            logger.info(f"Loaded {count} sample access requests")
    
    # Database query methods
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_system(self, system_id: str) -> Optional[Dict[str, Any]]:
        """Get system by ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM systems WHERE id = ?", (system_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def list_users(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List users with pagination."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM users ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_user_entitlements(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active entitlements for a user."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT e.*, s.name as system_name, s.sensitivity_tier
                FROM entitlements e
                JOIN systems s ON e.system_id = s.id
                WHERE e.user_id = ? AND e.is_active = 1
                ORDER BY s.name
            """, (user_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def store_decision(self, request_id: str, decision_data: Dict[str, Any]):
        """Store governance decision in database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO governance_decisions (
                    request_id, final_decision, processed_at, workflow_version,
                    reasoning, risk_analysis, policy_analysis, certification_analysis,
                    audit_trail, full_result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id,
                decision_data.get("final_decision"),
                decision_data.get("processed_at", datetime.now().isoformat()),
                decision_data.get("workflow_version"),
                decision_data.get("reasoning"),
                json.dumps(decision_data.get("risk_analysis", {})),
                json.dumps(decision_data.get("policy_analysis", {})),
                json.dumps(decision_data.get("certification_analysis", {})),
                json.dumps(decision_data.get("audit_trail", [])),
                json.dumps(decision_data)
            ))
            await db.commit()
    
    async def get_request_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get request status and decision."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM governance_decisions WHERE request_id = ?",
                (request_id,)
            )
            row = await cursor.fetchone()
            if row:
                result = dict(row)
                # Parse JSON fields
                for json_field in ['risk_analysis', 'policy_analysis', 'certification_analysis', 'audit_trail', 'full_result']:
                    if result.get(json_field):
                        try:
                            result[json_field] = json.loads(result[json_field])
                        except json.JSONDecodeError:
                            pass
                return result
            return None
    
    async def get_audit_trail(self, request_id: str) -> List[Dict[str, Any]]:
        """Get audit trail for a request."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM audit_records WHERE request_id = ? ORDER BY timestamp",
                (request_id,)
            )
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                record = dict(row)
                # Parse JSON fields
                for json_field in ['policies_evaluated', 'risk_factors', 'regulatory_considerations', 'metadata']:
                    if record.get(json_field):
                        try:
                            record[json_field] = json.loads(record[json_field])
                        except json.JSONDecodeError:
                            pass
                results.append(record)
            return results
    
    async def store_audit_record(self, audit_record: Dict[str, Any]):
        """Store an audit record."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO audit_records (
                    request_id, timestamp, agent_name, action, decision, reasoning,
                    confidence_score, policies_evaluated, risk_factors,
                    regulatory_considerations, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit_record.get("request_id"),
                audit_record.get("timestamp", datetime.now().isoformat()),
                audit_record.get("agent_name"),
                audit_record.get("action"),
                audit_record.get("decision"),
                audit_record.get("reasoning"),
                audit_record.get("confidence_score"),
                json.dumps(audit_record.get("policies_evaluated", [])),
                json.dumps(audit_record.get("risk_factors", [])),
                json.dumps(audit_record.get("regulatory_considerations", [])),
                json.dumps(audit_record.get("metadata", {}))
            ))
            await db.commit()
    
    async def close(self):
        """Close database connections."""
        # For aiosqlite, connections are managed per operation
        logger.info("Database connections closed")
    
    # Utility methods for tools
    
    async def get_policies_data(self) -> Dict[str, Any]:
        """Get all policies data for tools."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Get RBAC rules
            cursor = await db.execute("SELECT * FROM rbac_rules")
            rbac_rules = [dict(row) for row in await cursor.fetchall()]
            
            # Parse JSON fields
            for rule in rbac_rules:
                rule["access_levels"] = json.loads(rule.get("access_levels", "[]"))
                rule["conditions"] = json.loads(rule.get("conditions", "{}"))
                rule["exceptions"] = json.loads(rule.get("exceptions", "[]"))
            
            # Get SoD rules
            cursor = await db.execute("SELECT * FROM sod_rules")
            sod_rules = [dict(row) for row in await cursor.fetchall()]
            
            for rule in sod_rules:
                rule["conflicting_systems"] = json.loads(rule.get("conflicting_systems", "[]"))
                rule["conflicting_roles"] = json.loads(rule.get("conflicting_roles", "[]"))
                rule["exception_conditions"] = json.loads(rule.get("exception_conditions", "[]"))
            
            # Get regulatory constraints
            cursor = await db.execute("SELECT * FROM regulatory_constraints")
            regulatory_constraints = [dict(row) for row in await cursor.fetchall()]
            
            for constraint in regulatory_constraints:
                constraint["applies_to_systems"] = json.loads(constraint.get("applies_to_systems", "[]"))
                constraint["applies_to_roles"] = json.loads(constraint.get("applies_to_roles", "[]"))
            
            return {
                "rbac_rules": rbac_rules,
                "sod_rules": sod_rules,
                "regulatory_constraints": regulatory_constraints,
                "sensitivity_rules": [],  # Would be loaded from another table if needed
                "department_policies": []  # Would be loaded from another table if needed
            }