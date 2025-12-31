"""
FastAPI backend for AppLocker Policy Creator
"""
from fastapi import FastAPI, HTTPException, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from typing import List, Optional, Dict
import uuid
from datetime import datetime

from .models import Rule, RuleCreate, RuleUpdate, ExportRequest, RuleCollection
from .xml_generator import AppLockerXMLGenerator

app = FastAPI(
    title="AppLocker Policy Creator API",
    description="REST API for creating and managing AppLocker policies",
    version="1.0.0"
)


def normalize_conditions_for_comparison(conditions):
    """Normalize conditions list for duplicate comparison."""
    if not conditions:
        return []
    
    # Sort conditions by type, then by key values for consistent comparison
    normalized = []
    for cond in conditions:
        # Create a sorted tuple of key-value pairs for consistent comparison
        sorted_items = sorted(cond.items())
        normalized.append(tuple(sorted_items))
    
    # Sort the list of conditions
    return sorted(normalized)


def normalize_exceptions_for_comparison(exceptions):
    """Normalize exceptions list for duplicate comparison."""
    if not exceptions:
        return []
    
    normalized = []
    for exc in exceptions:
        sorted_items = sorted(exc.items())
        normalized.append(tuple(sorted_items))
    
    return sorted(normalized)


def is_duplicate_rule(rule1: Rule, rule2: Rule) -> bool:
    """
    Check if two rules are duplicates.
    Rules are considered duplicates if they have the same:
    - collection
    - action
    - user_or_group_sid (normalized - None/empty treated as same)
    - conditions (normalized and sorted)
    - exceptions (normalized and sorted)
    """
    # Normalize user_or_group_sid (None, empty string, or "S-1-1-0" for Everyone are treated as same)
    def normalize_sid(sid):
        if not sid or sid == "S-1-1-0" or sid.strip() == "":
            return None
        return sid.strip()
    
    sid1 = normalize_sid(rule1.user_or_group_sid)
    sid2 = normalize_sid(rule2.user_or_group_sid)
    
    # Compare basic properties
    if rule1.collection != rule2.collection:
        return False
    if rule1.action != rule2.action:
        return False
    if sid1 != sid2:
        return False
    
    # Compare conditions (normalized)
    cond1 = normalize_conditions_for_comparison(rule1.conditions or [])
    cond2 = normalize_conditions_for_comparison(rule2.conditions or [])
    if cond1 != cond2:
        return False
    
    # Compare exceptions (normalized)
    exc1 = normalize_exceptions_for_comparison(rule1.exceptions or [])
    exc2 = normalize_exceptions_for_comparison(rule2.exceptions or [])
    if exc1 != exc2:
        return False
    
    return True


def find_duplicate_rule(new_rule: Rule, existing_rules: List[Rule]) -> Optional[Rule]:
    """Find if a duplicate of the new rule already exists in the list."""
    for existing_rule in existing_rules:
        if is_duplicate_rule(new_rule, existing_rule):
            return existing_rule
    return None

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (replace with database in production)
rules_store: List[Rule] = []
enforcement_modes_store: Dict[str, str] = {}  # Store enforcement modes per collection
policy_version_store: str = "1"
xml_generator = AppLockerXMLGenerator()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "AppLocker Policy Creator API",
        "version": "1.0.0",
        "endpoints": {
            "rules": "/api/rules",
            "export": "/api/export/xml",
            "import": "/api/import/xml"
        }
    }


@app.get("/api/rules", response_model=List[Rule])
async def get_rules(collection: Optional[str] = None):
    """
    Get all rules, optionally filtered by collection type.
    
    Args:
        collection: Optional filter by collection type (Exe, Script, Dll, Msi, Appx)
    """
    if collection:
        return [rule for rule in rules_store if rule.collection.value == collection]
    return rules_store


@app.get("/api/rules/{rule_id}", response_model=Rule)
async def get_rule(rule_id: str):
    """Get a specific rule by ID."""
    rule = next((r for r in rules_store if r.id == rule_id), None)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.post("/api/rules", response_model=Rule, status_code=201)
async def create_rule(rule_data: RuleCreate):
    """Create a new rule."""
    new_rule = Rule(
        id=str(uuid.uuid4()),
        name=rule_data.name,
        description=rule_data.description,
        collection=rule_data.collection,
        action=rule_data.action,
        user_or_group_sid=rule_data.user_or_group_sid,
        conditions=rule_data.conditions,
        exceptions=rule_data.exceptions or [],
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    # Check for duplicates
    duplicate = find_duplicate_rule(new_rule, rules_store)
    if duplicate:
        # Return the existing rule instead of creating a duplicate
        return duplicate
    
    rules_store.append(new_rule)
    return new_rule


@app.put("/api/rules/{rule_id}", response_model=Rule)
async def update_rule(rule_id: str, rule_data: RuleUpdate):
    """Update an existing rule."""
    rule_index = next((i for i, r in enumerate(rules_store) if r.id == rule_id), None)
    if rule_index is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    existing_rule = rules_store[rule_index]
    
    # Update fields if provided
    if rule_data.name is not None:
        existing_rule.name = rule_data.name
    if rule_data.description is not None:
        existing_rule.description = rule_data.description
    if rule_data.collection is not None:
        existing_rule.collection = rule_data.collection
    if rule_data.action is not None:
        existing_rule.action = rule_data.action
    if rule_data.user_or_group_sid is not None:
        existing_rule.user_or_group_sid = rule_data.user_or_group_sid
    if rule_data.conditions is not None:
        existing_rule.conditions = rule_data.conditions
    if rule_data.exceptions is not None:
        existing_rule.exceptions = rule_data.exceptions
    
    existing_rule.updated_at = datetime.now()
    
    return existing_rule


@app.delete("/api/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str):
    """Delete a rule."""
    rule_index = next((i for i, r in enumerate(rules_store) if r.id == rule_id), None)
    if rule_index is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rules_store.pop(rule_index)
    return Response(status_code=204)


@app.delete("/api/rules", status_code=204)
async def delete_all_rules(collection: Optional[RuleCollection] = Query(None)):
    """Delete all rules, or all rules in a specific collection."""
    global rules_store
    if collection:
        # Delete only rules in the specified collection
        rules_store = [r for r in rules_store if r.collection != collection]
    else:
        # Delete all rules
        rules_store.clear()
    return Response(status_code=204)


@app.post("/api/export/xml")
async def export_xml(export_request: ExportRequest):
    """
    Export rules as AppLocker XML policy.
    Can export full policy or individual rule collections.
    
    Args:
        export_request: Export request with rules and options
    """
    try:
        from .models import RuleCollection
        
        # Use stored enforcement modes if available, otherwise use request or default
        global enforcement_modes_store, policy_version_store
        
        enforcement_modes: Dict[RuleCollection, str] = {}
        if enforcement_modes_store:
            # Convert stored enforcement modes back to RuleCollection keys
            for col_str, mode in enforcement_modes_store.items():
                try:
                    col = RuleCollection(col_str)
                    enforcement_modes[col] = mode
                except ValueError:
                    pass
        
        # If no stored modes, use request mode or default
        if not enforcement_modes:
            default_mode = export_request.enforcement_mode or "AuditOnly"
            if default_mode == "Enforced":
                default_mode = "Enabled"
            enforcement_modes[None] = default_mode  # Default for all collections
        
        version = export_request.version or policy_version_store or "1"
        
        xml_content = xml_generator.generate_policy(
            rules=export_request.rules,
            enforcement_modes=enforcement_modes,
            version=version,
            use_namespace=False  # Match original format without namespace
        )
        
        return Response(
            content=xml_content,
            media_type="application/xml",
            headers={
                "Content-Disposition": "attachment; filename=AppLockerPolicy.xml"
            }
        )
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=f"Invalid rule data: {str(ve)}")
    except Exception as e:
        import traceback
        error_detail = f"Failed to generate XML: {str(e)}\n{traceback.format_exc()}"
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Failed to generate XML: {str(e)}")


@app.post("/api/export/collection/{collection_type}")
async def export_collection(collection_type: str):
    """
    Export a single rule collection as XML (for Intune per-collection upload).
    Returns only the RuleCollection element without AppLockerPolicy wrapper.
    
    Args:
        collection_type: Collection type (Exe, Script, Dll, Msi, Appx)
    """
    try:
        from .models import RuleCollection
        from lxml import etree
        
        # Map collection type string to enum
        collection_map = {
            "Exe": RuleCollection.EXECUTABLE,
            "Script": RuleCollection.SCRIPT,
            "Dll": RuleCollection.DLL,
            "Msi": RuleCollection.MSI,
            "Appx": RuleCollection.PACKAGED_APP,
        }
        
        if collection_type not in collection_map:
            raise HTTPException(status_code=400, detail=f"Invalid collection type: {collection_type}")
        
        target_collection = collection_map[collection_type]
        
        # Filter rules for this collection
        collection_rules = [r for r in rules_store if r.collection == target_collection]
        
        if not collection_rules:
            raise HTTPException(status_code=404, detail=f"No rules found for collection type: {collection_type}")
        
        # Get enforcement mode for this collection
        global enforcement_modes_store
        enforcement_mode = enforcement_modes_store.get(collection_type, "AuditOnly")
        
        # Create the RuleCollection element directly (without AppLockerPolicy wrapper)
        collection_name_map = {
            RuleCollection.EXECUTABLE: "Exe",
            RuleCollection.SCRIPT: "Script",
            RuleCollection.DLL: "Dll",
            RuleCollection.MSI: "Msi",
            RuleCollection.PACKAGED_APP: "Appx",
        }
        
        collection_name = collection_name_map[target_collection]
        collection_elem = etree.Element("RuleCollection", Type=collection_name, EnforcementMode=enforcement_mode)
        
        # Add rules to collection
        for rule in collection_rules:
            rule_elem = xml_generator._create_rule(rule)
            collection_elem.append(rule_elem)
        
        # Generate XML string (just the RuleCollection, no wrapper)
        collection_xml = etree.tostring(
            collection_elem,
            encoding='unicode',
            pretty_print=True,
            xml_declaration=False
        )
        
        return Response(
            content=collection_xml,
            media_type="application/xml",
            headers={
                "Content-Disposition": f"attachment; filename=AppLocker_{collection_type}.xml"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"Failed to export collection: {str(e)}\n{traceback.format_exc()}"
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Failed to export collection: {str(e)}")


@app.post("/api/import/xml")
async def import_xml(xml_content: str = Body(..., media_type="text/plain")):
    """
    Import rules from an AppLocker XML policy.
    
    Args:
        xml_content: XML policy string (sent as plain text)
    """
    try:
        imported_rules, enforcement_modes, version = xml_generator.parse_xml(xml_content)
        
        if not imported_rules:
            raise HTTPException(status_code=400, detail="No rules found in XML file")
        
        # Store enforcement modes and version globally
        global enforcement_modes_store, policy_version_store
        enforcement_modes_store = {col.value: mode for col, mode in enforcement_modes.items()}
        policy_version_store = version
        
        # Validate and add imported rules to store with new IDs
        validated_rules = []
        skipped_duplicates = 0
        for i, rule in enumerate(imported_rules):
            try:
                # Ensure rule has required fields
                rule.id = str(uuid.uuid4())
                rule.created_at = datetime.now()
                rule.updated_at = datetime.now()
                
                # Validate the rule model
                validated_rule = Rule(**rule.dict())
                
                # Check for duplicates before adding
                duplicate = find_duplicate_rule(validated_rule, rules_store)
                if duplicate:
                    skipped_duplicates += 1
                    continue  # Skip duplicate, keep existing one
                
                validated_rules.append(validated_rule)
                rules_store.append(validated_rule)
            except Exception as rule_error:
                # Skip invalid rules but continue processing
                import traceback
                error_msg = f"Error processing rule {i+1} ({rule.name if hasattr(rule, 'name') else 'unknown'}): {str(rule_error)}"
                print(f"Warning: {error_msg}")
                print(traceback.format_exc())
                continue
        
        if not validated_rules and skipped_duplicates == 0:
            raise HTTPException(status_code=422, detail="No valid rules could be imported from XML")
        
        message = f"Successfully imported {len(validated_rules)} rules"
        if skipped_duplicates > 0:
            message += f" ({skipped_duplicates} duplicates skipped)"
        
        return {
            "message": message,
            "rules": validated_rules,
            "enforcement_modes": enforcement_modes_store,
            "version": version
        }
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=f"XML parsing error: {str(ve)}")
    except Exception as e:
        import traceback
        error_detail = f"Failed to import XML: {str(e)}\n{traceback.format_exc()}"
        print(error_detail)
        raise HTTPException(status_code=422, detail=f"Failed to import XML: {str(e)}")


@app.get("/api/collections")
async def get_collections():
    """Get available rule collection types."""
    return {
        "collections": [
            {
                "value": "Exe",
                "label": "Executable Rules",
                "description": "Controls execution of .exe and .com files",
                "file_types": [".exe", ".com"]
            },
            {
                "value": "Script",
                "label": "Script Rules",
                "description": "Controls execution of scripts (.ps1, .bat, .cmd, .vbs, .js)",
                "file_types": [".ps1", ".bat", ".cmd", ".vbs", ".js"]
            },
            {
                "value": "Dll",
                "label": "DLL Rules",
                "description": "Controls loading of DLL and OCX files",
                "file_types": [".dll", ".ocx"]
            },
            {
                "value": "Msi",
                "label": "Windows Installer Rules",
                "description": "Controls installation of .msi, .msp, .mst files",
                "file_types": [".msi", ".msp", ".mst"]
            },
            {
                "value": "Appx",
                "label": "Packaged App Rules",
                "description": "Controls UWP/MSIX packaged applications",
                "file_types": ["UWP/MSIX apps"]
            }
        ]
    }


@app.post("/api/import/default-rules")
async def import_default_rules(collection_type: Optional[str] = Query(None)):
    """
    Import default AppLocker rules.
    If collection_type is provided, only import rules for that collection.
    Otherwise, import all default rules.
    
    Args:
        collection_type: Optional collection type filter (Exe, Script, Dll, Msi, Appx)
    """
    global enforcement_modes_store, policy_version_store
    
    try:
        import os
        from pathlib import Path
        
        # Load default rules XML file
        default_rules_path = Path(__file__).parent / "default_rules.xml"
        
        if not default_rules_path.exists():
            raise HTTPException(status_code=500, detail="Default rules file not found")
        
        with open(default_rules_path, 'r', encoding='utf-8') as f:
            default_xml = f.read()
        
        # Parse the default rules
        imported_rules, enforcement_modes, version = xml_generator.parse_xml(default_xml)
        
        # Filter by collection type if specified
        if collection_type:
            collection_map = {
                "Exe": RuleCollection.EXECUTABLE,
                "Script": RuleCollection.SCRIPT,
                "Dll": RuleCollection.DLL,
                "Msi": RuleCollection.MSI,
                "Appx": RuleCollection.PACKAGED_APP,
            }
            if collection_type not in collection_map:
                raise HTTPException(status_code=400, detail=f"Invalid collection type: {collection_type}")
            
            target_collection = collection_map[collection_type]
            imported_rules = [r for r in imported_rules if r.collection == target_collection]
            
            # Store enforcement mode for this collection
            if target_collection in enforcement_modes:
                enforcement_modes_store[collection_type] = enforcement_modes[target_collection]
        else:
            # Store all enforcement modes
            enforcement_modes_store = {col.value: mode for col, mode in enforcement_modes.items()}
            policy_version_store = version
        
        if not imported_rules:
            raise HTTPException(status_code=404, detail="No default rules found for the specified collection")
        
        # Add imported rules to store with new IDs
        validated_rules = []
        skipped_duplicates = 0
        for i, rule in enumerate(imported_rules):
            try:
                # Ensure rule has required fields
                rule.id = str(uuid.uuid4())
                rule.created_at = datetime.now()
                rule.updated_at = datetime.now()
                
                # Validate the rule model
                validated_rule = Rule(**rule.dict())
                
                # Check for duplicates before adding
                duplicate = find_duplicate_rule(validated_rule, rules_store)
                if duplicate:
                    skipped_duplicates += 1
                    continue  # Skip duplicate, keep existing one
                
                validated_rules.append(validated_rule)
                rules_store.append(validated_rule)
            except Exception as rule_error:
                # Skip invalid rules but continue processing
                import traceback
                error_msg = f"Error processing rule {i+1} ({rule.name if hasattr(rule, 'name') else 'unknown'}): {str(rule_error)}"
                print(f"Warning: {error_msg}")
                print(traceback.format_exc())
                continue
        
        if not validated_rules and skipped_duplicates == 0:
            raise HTTPException(status_code=422, detail="No valid default rules could be imported")
        
        message = f"Successfully imported {len(validated_rules)} default rules"
        if skipped_duplicates > 0:
            message += f" ({skipped_duplicates} duplicates skipped)"
        
        return {
            "message": message,
            "rules": validated_rules
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"Failed to import default rules: {str(e)}\n{traceback.format_exc()}"
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Failed to import default rules: {str(e)}")


@app.get("/api/default-rules")
async def get_default_rules():
    """Get default AppLocker rule templates."""
    return {
        "default_rules": [
            {
                "name": "Allow Windows and Program Files (Executables)",
                "description": "Default rule to allow executables from Windows and Program Files directories",
                "collection": "Exe",
                "action": "Allow",
                "conditions": [
                    {
                        "type": "FilePathCondition",
                        "path": "%WINDIR%\\*"
                    },
                    {
                        "type": "FilePathCondition",
                        "path": "%PROGRAMFILES%\\*"
                    }
                ]
            },
            {
                "name": "Allow Windows and Program Files (Scripts)",
                "description": "Default rule to allow scripts from Windows and Program Files directories",
                "collection": "Script",
                "action": "Allow",
                "conditions": [
                    {
                        "type": "FilePathCondition",
                        "path": "%WINDIR%\\*"
                    },
                    {
                        "type": "FilePathCondition",
                        "path": "%PROGRAMFILES%\\*"
                    }
                ]
            },
            {
                "name": "Allow Administrators (All)",
                "description": "Allow all files for administrators",
                "collection": "Exe",
                "action": "Allow",
                "user_or_group_sid": "S-1-5-32-544",  # Administrators group
                "conditions": [
                    {
                        "type": "FilePathCondition",
                        "path": "*"
                    }
                ]
            }
        ]
    }

