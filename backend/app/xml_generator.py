"""
AppLocker XML Policy Generator

Generates valid AppLocker XML policies conforming to Microsoft's schema.
"""
from typing import List, Dict, Any, Optional, Tuple
from lxml import etree
from datetime import datetime
from .models import Rule, RuleCollection, Action


class AppLockerXMLGenerator:
    """Generates AppLocker XML policies."""
    
    # Namespace for AppLocker XML
    NS = "http://schemas.microsoft.com/applocker/v1"
    
    def __init__(self):
        self.nsmap = {None: self.NS}
    
    def generate_policy(self, rules: List[Rule], enforcement_modes: Optional[Dict[RuleCollection, str]] = None, version: str = "1", use_namespace: bool = False) -> str:
        """
        Generate a complete AppLocker XML policy.
        
        Args:
            rules: List of Rule objects
            enforcement_modes: Dict mapping collection type to enforcement mode (per collection)
            version: Policy version string
            use_namespace: Whether to include XML namespace (default: False to match original format)
            
        Returns:
            XML string conforming to AppLocker schema
        """
        # Create root element (without namespace to match original format)
        if use_namespace:
            root = etree.Element("AppLockerPolicy", Version=version, nsmap=self.nsmap)
        else:
            root = etree.Element("AppLockerPolicy", Version=version)
        
        # Group rules by collection type
        rules_by_collection: Dict[RuleCollection, List[Rule]] = {
            RuleCollection.EXECUTABLE: [],
            RuleCollection.SCRIPT: [],
            RuleCollection.DLL: [],
            RuleCollection.MSI: [],
            RuleCollection.PACKAGED_APP: [],
        }
        
        for rule in rules:
            rules_by_collection[rule.collection].append(rule)
        
        # Default enforcement modes if not provided
        if enforcement_modes is None:
            enforcement_modes = {}
        default_enforcement = enforcement_modes.get(None, "AuditOnly")
        
        # Create collection elements for each type that has rules
        for collection_type, collection_rules in rules_by_collection.items():
            if collection_rules:
                # Use collection-specific enforcement mode or default
                collection_enforcement = enforcement_modes.get(collection_type, default_enforcement)
                collection_elem = self._create_collection(collection_type, collection_rules, collection_enforcement)
                root.append(collection_elem)
        
        # Generate XML string with proper formatting
        xml_string = etree.tostring(
            root,
            encoding='unicode',
            pretty_print=True,
            xml_declaration=False
        )
        
        # Only add XML declaration if original had it (check if it starts with <?xml)
        # For now, we'll match the original which doesn't have it
        return xml_string
    
    def _create_collection(self, collection_type: RuleCollection, rules: List[Rule], enforcement_mode: str) -> etree.Element:
        """Create a rule collection element, preserving rule order."""
        collection_name_map = {
            RuleCollection.EXECUTABLE: "Exe",
            RuleCollection.SCRIPT: "Script",
            RuleCollection.DLL: "Dll",
            RuleCollection.MSI: "Msi",
            RuleCollection.PACKAGED_APP: "Appx",
        }
        
        collection_name = collection_name_map[collection_type]
        collection_elem = etree.Element(f"RuleCollection", Type=collection_name, EnforcementMode=enforcement_mode)
        
        # Preserve original order of rules (don't sort)
        for rule in rules:
            rule_elem = self._create_rule(rule)
            collection_elem.append(rule_elem)
        
        return collection_elem
    
    def _create_rule(self, rule: Rule) -> etree.Element:
        """Create a rule element using attributes format to match original."""
        rule_id = rule.id or self._generate_rule_id(rule)
        
        # Determine rule element type based on conditions
        # If all conditions are hash conditions -> FileHashRule
        # If all conditions are publisher conditions -> FilePublisherRule
        # Otherwise -> FilePathRule
        rule_type = self._determine_rule_type(rule.conditions)
        
        # Set user or group (default to Everyone SID)
        user_sid = rule.user_or_group_sid or "S-1-1-0"  # Everyone SID
        
        # Create rule element with attributes (matching original format)
        rule_elem = etree.Element(
            rule_type,
            Id=rule_id,
            Name=rule.name,
            Description=rule.description or "",
            UserOrGroupSid=user_sid,
            Action=rule.action.value
        )
        
        # Add conditions
        conditions_elem = etree.SubElement(rule_elem, "Conditions")
        for condition in rule.conditions:
            condition_elem = self._create_condition(condition)
            conditions_elem.append(condition_elem)
        
        # Add exceptions if present (for FilePathRule)
        if rule.exceptions and len(rule.exceptions) > 0:
            exceptions_elem = etree.SubElement(rule_elem, "Exceptions")
            for exception in rule.exceptions:
                if exception.get("type") == "FilePathCondition":
                    exc_elem = etree.SubElement(exceptions_elem, "FilePathCondition", Path=exception.get("path", ""))
        
        return rule_elem
    
    def _determine_rule_type(self, conditions: List[Dict[str, Any]]) -> str:
        """Determine the XML rule element type based on conditions."""
        if not conditions:
            return "FilePathRule"
        
        condition_types = [cond.get("type", "") for cond in conditions]
        
        # If all conditions are hash conditions, use FileHashRule
        if all(ct == "FileHashCondition" for ct in condition_types):
            return "FileHashRule"
        
        # If all conditions are publisher conditions, use FilePublisherRule
        if all(ct == "FilePublisherCondition" for ct in condition_types):
            return "FilePublisherRule"
        
        # Otherwise, use FilePathRule (default)
        return "FilePathRule"
    
    def _create_condition(self, condition: Dict[str, Any]) -> etree.Element:
        """Create a condition element based on condition type."""
        condition_type = condition.get("type", "")
        
        # Determine condition type from type field or by checking for key presence
        if condition_type == "FilePathCondition" or (not condition_type and "path" in condition):
            return self._create_path_condition(condition)
        elif condition_type == "FilePublisherCondition" or (not condition_type and "publisher_name" in condition):
            return self._create_publisher_condition(condition)
        elif condition_type == "FileHashCondition" or (not condition_type and "file_hash" in condition):
            return self._create_hash_condition(condition)
        else:
            # Default to path condition if type is unclear
            if "path" in condition:
                return self._create_path_condition(condition)
            raise ValueError(f"Unknown condition type: {condition_type or 'unknown'}")
    
    def _create_path_condition(self, condition: Dict[str, Any]) -> etree.Element:
        """Create a file path condition."""
        path_elem = etree.Element("FilePathCondition", Path=condition.get("path", ""))
        return path_elem
    
    def _create_publisher_condition(self, condition: Dict[str, Any]) -> etree.Element:
        """Create a file publisher condition using attributes format to match original."""
        # Use attributes format to match original AppLocker XML
        pub_name = condition.get("publisher_name") or "*"
        product_name = condition.get("product_name") or "*"
        binary_name = condition.get("binary_name") or "*"
        
        pub_elem = etree.Element(
            "FilePublisherCondition",
            PublisherName=str(pub_name),
            ProductName=str(product_name),
            BinaryName=str(binary_name)
        )
        
        # Binary version range
        version = condition.get("version", "*")
        if isinstance(version, str) and "-" in version:
            # Handle version range like "0.0.0.0-*"
            parts = version.split("-", 1)
            low_section = parts[0] if parts[0] else "*"
            high_section = parts[1] if len(parts) > 1 else "*"
        else:
            low_section = version if version != "*" else "*"
            high_section = version if version != "*" else "*"
        
        binary_version_range = etree.SubElement(pub_elem, "BinaryVersionRange")
        binary_version_range.set("LowSection", low_section)
        binary_version_range.set("HighSection", high_section)
        
        return pub_elem
    
    def _create_hash_condition(self, condition: Dict[str, Any]) -> etree.Element:
        """Create a file hash condition with potentially multiple FileHash elements."""
        hash_elem = etree.Element("FileHashCondition")
        
        # Check if this condition has multiple hashes (from grouped parsing)
        hashes = condition.get("hashes", [])
        
        # If no hashes array, create one from the single hash fields (backward compatibility)
        if not hashes:
            hashes = [{
                "file_hash": condition.get("file_hash", ""),
                "hash_type": condition.get("hash_type", "SHA256"),
                "source_file_name": condition.get("source_file_name", ""),
                "source_file_length": condition.get("source_file_length"),
            }]
        
        # Create a FileHash element for each hash
        for hash_item in hashes:
            file_hash = etree.SubElement(hash_elem, "FileHash")
            file_hash.set("Type", hash_item.get("hash_type", "SHA256"))
            
            # Add 0x prefix to hash data to match original format
            hash_data = hash_item.get("file_hash", "")
            if hash_data and not hash_data.startswith("0x") and not hash_data.startswith("0X"):
                hash_data = "0x" + hash_data.upper()
            
            file_hash.set("Data", hash_data)
            file_hash.set("SourceFileName", hash_item.get("source_file_name", ""))
            
            source_file_length = hash_item.get("source_file_length")
            if source_file_length:
                file_hash.set("SourceFileLength", str(source_file_length))
        
        return hash_elem
    
    def _generate_rule_id(self, rule: Rule) -> str:
        """Generate a unique rule ID."""
        import uuid
        return str(uuid.uuid4())
    
    def parse_xml(self, xml_string: str) -> Tuple[List[Rule], Dict[RuleCollection, str], str]:
        """
        Parse an existing AppLocker XML policy into Rule objects.
        Supports both full AppLockerPolicy and individual RuleCollection elements.
        
        Args:
            xml_string: XML policy string (full policy or single RuleCollection)
            
        Returns:
            Tuple of (List of Rule objects, Dict of enforcement modes per collection, version)
        """
        try:
            root = etree.fromstring(xml_string.encode('utf-8'))
            rules = []
            enforcement_modes: Dict[RuleCollection, str] = {}
            version = "1"
            
            # Get namespace from root if present, otherwise use empty string
            ns = root.nsmap.get(None, "") if hasattr(root, 'nsmap') else ""
            if ns:
                ns_prefix = "{" + ns + "}"
            else:
                ns_prefix = ""
            
            # Check if root is AppLockerPolicy or RuleCollection
            if root.tag.endswith("AppLockerPolicy") or root.tag == "AppLockerPolicy":
                version = root.get("Version", "1")
                # Find all RuleCollection elements (with or without namespace)
                collections = root.findall(f".//{ns_prefix}RuleCollection")
                if not collections:
                    collections = root.findall(".//RuleCollection")
            elif root.tag.endswith("RuleCollection") or root.tag == "RuleCollection":
                # Single RuleCollection element - treat as list with one item
                collections = [root]
            else:
                raise ValueError(f"Unexpected root element: {root.tag}")
            
            for collection in collections:
                collection_type_str = collection.get("Type", "")
                collection_type = self._map_collection_type(collection_type_str)
                
                # Store enforcement mode for this collection
                enforcement_mode = collection.get("EnforcementMode", "AuditOnly")
                enforcement_modes[collection_type] = enforcement_mode
                
                # Find all rule types in document order (preserve original order)
                # We need to iterate through children to preserve order
                rule_elements = []
                for child in collection:
                    tag = child.tag
                    # Remove namespace prefix if present
                    if ns_prefix and tag.startswith(ns_prefix):
                        tag = tag[len(ns_prefix):]
                    elif "}" in tag:
                        tag = tag.split("}")[-1]
                    
                    # Check if it's a rule element
                    if tag in ("FilePathRule", "FileHashRule", "FilePublisherRule"):
                        rule_elements.append(child)
                
                # Fallback: if no rules found by iterating, try findall (but this may change order)
                if not rule_elements:
                    rule_elements = (
                        collection.findall(f".//{ns_prefix}FilePathRule") +
                        collection.findall(f".//{ns_prefix}FileHashRule") +
                        collection.findall(f".//{ns_prefix}FilePublisherRule")
                    )
                    if not rule_elements:
                        rule_elements = (
                            collection.findall(".//FilePathRule") +
                            collection.findall(".//FileHashRule") +
                            collection.findall(".//FilePublisherRule")
                        )
                
                for rule_elem in rule_elements:
                    rule = self._parse_rule_element(rule_elem, collection_type, ns_prefix)
                    rules.append(rule)
            
            return rules, enforcement_modes, version
        except Exception as e:
            raise ValueError(f"Failed to parse XML: {str(e)}")
    
    def _map_collection_type(self, type_str: str) -> RuleCollection:
        """Map XML collection type string to RuleCollection enum."""
        mapping = {
            "Exe": RuleCollection.EXECUTABLE,
            "Script": RuleCollection.SCRIPT,
            "Dll": RuleCollection.DLL,
            "Msi": RuleCollection.MSI,
            "Appx": RuleCollection.PACKAGED_APP,
        }
        return mapping.get(type_str, RuleCollection.EXECUTABLE)
    
    def _parse_rule_element(self, rule_elem: etree.Element, collection_type: RuleCollection, ns_prefix: str = "") -> Rule:
        """Parse a rule element into a Rule object."""
        rule_id = rule_elem.get("Id", "")
        name = rule_elem.get("Name", "")
        description = rule_elem.get("Description", "")
        
        # Parse user or group SID - can be attribute or child element
        user_sid = rule_elem.get("UserOrGroupSid")
        if not user_sid:
            user_sid_elem = rule_elem.find(f".//{ns_prefix}UserOrGroupSid")
            if user_sid_elem is None:
                user_sid_elem = rule_elem.find(".//UserOrGroupSid")
            user_sid = user_sid_elem.text if user_sid_elem is not None else "S-1-1-0"
        
        # Parse action - can be attribute or child element
        action_str = rule_elem.get("Action")
        if not action_str:
            action_elem = rule_elem.find(f".//{ns_prefix}Action")
            if action_elem is None:
                action_elem = rule_elem.find(".//Action")
            action_str = action_elem.text if action_elem is not None else "Allow"
        action = Action.ALLOW if action_str == "Allow" else Action.DENY
        
        # Parse conditions
        conditions = []
        # Conditions can be in a Conditions element or direct children
        conditions_elem = rule_elem.find(f".//{ns_prefix}Conditions")
        if conditions_elem is None:
            conditions_elem = rule_elem.find(".//Conditions")
        
        # Search scope: within Conditions element if it exists, otherwise within rule element
        search_root = conditions_elem if conditions_elem is not None else rule_elem
        
        if search_root is not None:
            # Path conditions
            path_conditions = search_root.findall(f".//{ns_prefix}FilePathCondition")
            if not path_conditions:
                path_conditions = search_root.findall(".//FilePathCondition")
            for path_cond in path_conditions:
                conditions.append({
                    "type": "FilePathCondition",
                    "path": path_cond.get("Path", "")
                })
            
            # Publisher conditions - can be direct child of rule or in Conditions
            pub_conditions = search_root.findall(f".//{ns_prefix}FilePublisherCondition")
            if not pub_conditions:
                pub_conditions = search_root.findall(".//FilePublisherCondition")
            for pub_cond in pub_conditions:
                # PublisherName can be child element or attribute
                pub_name = pub_cond.get("PublisherName")
                if not pub_name:
                    pub_name_elem = pub_cond.find(f".//{ns_prefix}PublisherName")
                    if pub_name_elem is None:
                        pub_name_elem = pub_cond.find(".//PublisherName")
                    pub_name = pub_name_elem.text if pub_name_elem is not None else "*"
                
                product_elem = pub_cond.find(f".//{ns_prefix}ProductName")
                if product_elem is None:
                    product_elem = pub_cond.find(".//ProductName")
                binary_elem = pub_cond.find(f".//{ns_prefix}BinaryName")
                if binary_elem is None:
                    binary_elem = pub_cond.find(".//BinaryName")
                version_elem = pub_cond.find(f".//{ns_prefix}BinaryVersionRange")
                if version_elem is None:
                    version_elem = pub_cond.find(".//BinaryVersionRange")
                
                # Get product and binary names, default to "*" if not found
                product_name = product_elem.text if product_elem is not None and product_elem.text else "*"
                binary_name = binary_elem.text if binary_elem is not None and binary_elem.text else "*"
                
                condition = {
                    "type": "FilePublisherCondition",
                    "publisher_name": pub_name,
                    "product_name": product_name,
                    "binary_name": binary_name,
                }
                
                if version_elem is not None:
                    low_section = version_elem.get("LowSection", "*")
                    high_section = version_elem.get("HighSection", "*")
                    condition["version"] = low_section if low_section == high_section else f"{low_section}-{high_section}"
                else:
                    condition["version"] = "*"
                
                conditions.append(condition)
            
            # Hash conditions - can have multiple FileHash elements within a single FileHashCondition
            hash_conditions = search_root.findall(f".//{ns_prefix}FileHashCondition")
            if not hash_conditions:
                hash_conditions = search_root.findall(".//FileHashCondition")
            for hash_cond in hash_conditions:
                # Find all FileHash elements within this condition
                file_hash_elems = hash_cond.findall(f".//{ns_prefix}FileHash")
                if not file_hash_elems:
                    file_hash_elems = hash_cond.findall(".//FileHash")
                
                # Group all FileHash elements from this FileHashCondition into a single condition
                # with a hashes array
                hashes = []
                for file_hash_elem in file_hash_elems:
                    hash_data = file_hash_elem.get("Data", "")
                    # Remove 0x prefix if present
                    if hash_data.startswith("0x") or hash_data.startswith("0X"):
                        hash_data = hash_data[2:]
                    
                    hashes.append({
                        "file_hash": hash_data,
                        "hash_type": file_hash_elem.get("Type", "SHA256"),
                        "source_file_name": file_hash_elem.get("SourceFileName", ""),
                        "source_file_length": file_hash_elem.get("SourceFileLength"),
                    })
                
                if hashes:
                    # Create a single condition with multiple hashes
                    conditions.append({
                        "type": "FileHashCondition",
                        "hashes": hashes,
                        # For backward compatibility, also include the first hash at the top level
                        "file_hash": hashes[0]["file_hash"],
                        "hash_type": hashes[0]["hash_type"],
                        "source_file_name": hashes[0]["source_file_name"],
                        "source_file_length": hashes[0]["source_file_length"],
                    })
        
        # Parse exceptions (for FilePathRule)
        exceptions = []
        exceptions_elem = rule_elem.find(f".//{ns_prefix}Exceptions")
        if exceptions_elem is None:
            exceptions_elem = rule_elem.find(".//Exceptions")
        
        if exceptions_elem is not None:
            # Exceptions are typically FilePathCondition elements
            exception_paths = exceptions_elem.findall(f".//{ns_prefix}FilePathCondition")
            if not exception_paths:
                exception_paths = exceptions_elem.findall(".//FilePathCondition")
            for exc_path in exception_paths:
                exceptions.append({
                    "type": "FilePathCondition",
                    "path": exc_path.get("Path", "")
                })
        
        return Rule(
            id=rule_id,
            name=name,
            description=description,
            collection=collection_type,
            action=action,
            user_or_group_sid=user_sid,
            conditions=conditions,
            exceptions=exceptions if exceptions else []
        )

