#!/usr/bin/env python3

import argparse
import requests
import json
import sys
import os
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin
import pymongo
from typing import List, Dict, Optional


class DecoyDexIntegration:
    def __init__(self, decoydex_url: str, verify_ssl: bool = True):
        # Validate URL format
        if not decoydex_url.startswith(('http://', 'https://')):
            raise ValueError("Invalid DecoyDex URL format")

        self.base_url = decoydex_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Melissae-Manager/2.7',
            'Content-Type': 'application/json'
        })

        # Set timeouts for all requests
        self.session.request = lambda *args, **kwargs: requests.Session.request(
            self.session, *args, timeout=kwargs.pop('timeout', 30), **kwargs
        )

    def enroll(self, token: str, challenge: str, manager_url: str,
               manager_name: Optional[str] = None) -> Dict:

        endpoint = urljoin(self.base_url, '/api/managers/enroll/complete')

        # Get manager metadata
        metadata = self._get_manager_metadata(manager_name)

        payload = {
            'token': token,
            'challenge': challenge,
            'metadata': metadata
        }

        try:
            response = self.session.post(
                endpoint,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()

            if data.get('success'):
                # Save API key to config file
                self._save_api_key(data['api_key'], data['ingest_endpoint'])

                print(f"✅ Enrollment successful!")
                print(f"   Manager ID: {data['manager_id']}")
                print(f"   Hunter: {data['hunter']}")
                print(f"   Ingest Endpoint: {data['ingest_endpoint']}")
                print(f"\n⚠️  API Key saved to: /etc/melissae/decoydex.conf")
                print(f"   Keep this file secure!")

                return data
            else:
                print(f"❌ Enrollment failed: {data.get('error', 'Unknown error')}")
                sys.exit(1)

        except requests.exceptions.RequestException as e:
            print(f"❌ Network error during enrollment: {e}")
            sys.exit(1)

    def sync_iocs(self, api_key: str, since_hours: int = 1,
                  batch_size: int = 100) -> Dict:

        # Load config
        config = self._load_config()
        if not config:
            print("❌ Configuration file not found. Run enrollment first.")
            sys.exit(1)

        ingest_url = config['ingest_endpoint']

        # Get IoCs from MongoDB
        iocs = self._fetch_iocs_from_db(since_hours)

        if not iocs:
            print(f"ℹ️  No new IoCs to sync (last {since_hours} hours)")
            return {'synced': 0}

        print(f"📤 Syncing {len(iocs)} IoCs to DecoyDex...")

        # Send in batches
        total_synced = 0
        total_points = 0

        for i in range(0, len(iocs), batch_size):
            batch = iocs[i:i + batch_size]

            try:
                response = self.session.post(
                    ingest_url,
                    json={'iocs': batch},
                    headers={'X-API-Key': api_key},
                    verify=self.verify_ssl,
                    timeout=60
                )
                response.raise_for_status()

                data = response.json()

                if data.get('success'):
                    processed = data['processed']
                    total_synced += processed['new'] + processed['existing']
                    total_points += processed['points_earned']

                    print(f"   Batch {i // batch_size + 1}: "
                          f"{processed['new']} new, "
                          f"{processed['existing']} existing, "
                          f"+{processed['points_earned']} points")
                else:
                    print(f"   ⚠️  Batch {i // batch_size + 1} failed: {data.get('error')}")

            except requests.exceptions.RequestException as e:
                print(f"   ❌ Batch {i // batch_size + 1} error: {e}")

        print(f"\n✅ Sync complete!")
        print(f"   Total synced: {total_synced} IoCs")
        print(f"   Points earned: {total_points}")

        return {
            'synced': total_synced,
            'points': total_points
        }

    def test_connection(self, api_key: str) -> bool:
        config = self._load_config()
        if not config:
            print("❌ Configuration file not found")
            return False

        ingest_url = config['ingest_endpoint']

        try:
            response = self.session.post(
                ingest_url,
                json={'iocs': []},  # Empty batch for testing
                headers={'X-API-Key': api_key},
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                print("✅ Connection successful!")
                print(f"   Endpoint: {ingest_url}")
                return True
            elif response.status_code == 401:
                print("❌ Invalid API key")
                return False
            else:
                print(f"❌ Connection failed: HTTP {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            return False

    def _get_manager_metadata(self, manager_name: Optional[str] = None) -> Dict:
        """
        Gather manager metadata for enrollment
        """
        # Try to get stats from MongoDB
        try:
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
            client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = client['melissae']

            log_count = db.logs.count_documents({})
            agent_count = db.agents.count_documents({})

            # Get protocols
            protocols = db.logs.distinct('protocol')

            return {
                'name': manager_name or os.getenv('HOSTNAME', 'melissae-manager'),
                'version': '2.7',
                'agent_count': agent_count,
                'total_logs': log_count,
                'protocols': protocols[:10]  # Limit to 10
            }
        except Exception:
            # Fallback if MongoDB not accessible
            return {
                'name': manager_name or 'melissae-manager',
                'version': '2.7'
            }

    def _fetch_iocs_from_db(self, since_hours: int) -> List[Dict]:
        try:
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
            client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = client['melissae']

            # Calculate time threshold
            since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

            # Get threats (IPs with matched rules)
            threats = list(db.threats.find({
                'last_seen': {'$gte': since.isoformat()}
            }))

            print(f"  → Found {len(threats)} threats in database")

            # Convert to DecoyDex format
            iocs = []
            for threat in threats:
                ip = threat.get('ip')
                if not ip:
                    continue

                # Get verdict and score from Melissae
                verdict = threat.get('verdict', 'suspicious')
                score = threat.get('protocol-score', 50)

                # Extract rule names with IDs (e.g., "HTTP probing [MLS006]")
                rules = []
                for rule in threat.get('rules', []):
                    rule_text = f"{rule.get('name', 'Unknown')} [{rule.get('id', 'N/A')}]"
                    rules.append(rule_text)

                # Get protocols from reasons or default
                protocols = []
                for agent_id in threat.get('agents', []):
                    # Try to find protocols from logs
                    log = db.logs.find_one({'ip': ip, 'agent_id': agent_id})
                    if log and log.get('protocol'):
                        protocols.append(log['protocol'])

                # Extract GeoIP and ASN data from Melissae threat
                geo = threat.get('geo', {})
                geoip_data = {}
                asn_data = {}

                if geo:
                    # Map Melissae geo fields to DecoyDex format
                    if geo.get('country'):
                        geoip_data['country'] = geo['country']
                    if geo.get('country_code'):
                        geoip_data['country_code'] = geo['country_code']
                    if geo.get('city'):
                        geoip_data['city'] = geo['city']
                    if geo.get('lat') is not None and geo.get('lon') is not None:
                        geoip_data['latitude'] = geo['lat']
                        geoip_data['longitude'] = geo['lon']

                    # ASN information from ISP/Org
                    if geo.get('isp'):
                        asn_data['isp'] = geo['isp']
                    if geo.get('org'):
                        asn_data['org'] = geo['org']

                ioc = {
                    'type': 'ip',
                    'value': ip,
                    'verdict': verdict,
                    'score': min(score, 100),  # Cap at 100
                    'protocols': list(set(protocols)) if protocols else [],
                    'tags': threat.get('tags', []),
                    'rules': rules,  # Real Melissae rules (MLSXXX)
                    'geoip': geoip_data,
                    'asn': asn_data
                }

                iocs.append(ioc)

            return iocs

        except Exception as e:
            print(f"❌ Error fetching IoCs from database: {e}")
            return []

    def _generate_tags(self, ioc_data: Dict) -> List[str]:
        tags = []

        # Add protocol tags
        protocols = ioc_data.get('protocols', [])
        for proto in protocols[:5]:  # Limit to 5
            if proto:
                tags.append(proto.lower())

        # Add count-based tags
        count = ioc_data.get('count', 0)
        if count > 100:
            tags.append('high_volume')
        elif count > 10:
            tags.append('medium_volume')

        return tags

    def _save_api_key(self, api_key: str, ingest_endpoint: str):
        # Validate inputs
        if not api_key or len(api_key) < 32:
            raise ValueError("Invalid API key")

        if not ingest_endpoint.startswith(('http://', 'https://')):
            raise ValueError("Invalid ingest endpoint")

        # Use home directory if /etc not writable
        if os.access('/etc', os.W_OK):
            config_dir = '/etc/melissae'
        else:
            config_dir = os.path.expanduser('~/.melissae')
        config_file = os.path.join(config_dir, 'decoydex.conf')

        # Create directory if it doesn't exist
        os.makedirs(config_dir, mode=0o700, exist_ok=True)

        config = {
            'api_key': api_key,
            'ingest_endpoint': ingest_endpoint,
            'enrolled_at': datetime.now(timezone.utc).isoformat()
        }

        # Write with restrictive permissions (atomic write)
        temp_file = config_file + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(config, f, indent=2)

        # Set file permissions before moving
        os.chmod(temp_file, 0o600)

        # Atomic rename
        os.rename(temp_file, config_file)

    def _load_config(self) -> Optional[Dict]:
        """
        Load DecoyDex configuration
        """
        # Try /etc first, fallback to home
        config_file = '/etc/melissae/decoydex.conf'
        if not os.path.exists(config_file):
            config_file = os.path.expanduser('~/.melissae/decoydex.conf')

        if not os.path.exists(config_file):
            return None

        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None


def main():
    parser = argparse.ArgumentParser(
        description='Melissae to DecoyDex Integration'
    )

    parser.add_argument(
        'command',
        choices=['enroll', 'sync', 'test'],
        help='Command to execute'
    )

    parser.add_argument(
        '--decoydex-url',
        default=os.getenv('DECOYDEX_URL', 'https://decoydex.example.com'),
        help='DecoyDex base URL'
    )

    parser.add_argument(
        '--token',
        help='Enrollment token (for enroll command)'
    )

    parser.add_argument(
        '--challenge',
        help='Challenge response (for enroll command)'
    )

    parser.add_argument(
        '--manager-url',
        default=os.getenv('MANAGER_URL'),
        help='This manager\'s URL (for enroll command)'
    )

    parser.add_argument(
        '--manager-name',
        help='Friendly name for this manager'
    )

    parser.add_argument(
        '--api-key',
        help='API key (for sync/test commands)'
    )

    parser.add_argument(
        '--since-hours',
        type=int,
        default=1,
        help='Sync IoCs from last N hours (default: 1)'
    )

    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL verification (not recommended)'
    )

    args = parser.parse_args()

    # Initialize integration
    integration = DecoyDexIntegration(
        args.decoydex_url,
        verify_ssl=not args.no_verify_ssl
    )

    # Execute command
    if args.command == 'enroll':
        if not args.token or not args.challenge:
            print("❌ --token and --challenge are required for enrollment")
            sys.exit(1)

        if not args.manager_url:
            print("❌ --manager-url is required for enrollment")
            sys.exit(1)

        integration.enroll(
            args.token,
            args.challenge,
            args.manager_url,
            args.manager_name
        )

    elif args.command == 'sync':
        if not args.api_key:
            # Try to load from config
            config = integration._load_config()
            if config:
                args.api_key = config['api_key']
            else:
                print("❌ --api-key is required or run enrollment first")
                sys.exit(1)

        integration.sync_iocs(args.api_key, args.since_hours)

    elif args.command == 'test':
        if not args.api_key:
            config = integration._load_config()
            if config:
                args.api_key = config['api_key']
            else:
                print("❌ --api-key is required or run enrollment first")
                sys.exit(1)

        integration.test_connection(args.api_key)


if __name__ == '__main__':
    main()
