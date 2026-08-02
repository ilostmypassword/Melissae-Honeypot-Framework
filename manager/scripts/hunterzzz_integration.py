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


class HunterzzzIntegration:
    def __init__(self, hunterzzz_url: str, verify_ssl: bool = True):
        self.base_url = hunterzzz_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Melissae-Manager/2.6',
            'Content-Type': 'application/json'
        })

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
                print(f"\n⚠️  API Key saved to: /etc/melissae/hunterzzz.conf")
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

        print(f"📤 Syncing {len(iocs)} IoCs to Hunterzzz...")

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
                'version': '2.6',
                'agent_count': agent_count,
                'total_logs': log_count,
                'protocols': protocols[:10]  # Limit to 10
            }
        except Exception:
            # Fallback if MongoDB not accessible
            return {
                'name': manager_name or 'melissae-manager',
                'version': '2.6'
            }

    def _fetch_iocs_from_db(self, since_hours: int) -> List[Dict]:
        try:
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
            client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = client['melissae']

            # Calculate time threshold
            since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

            # Aggregate unique IPs with their protocols and rules
            pipeline = [
                {
                    '$match': {
                        'timestamp': {'$gte': since.isoformat()},
                        'ip': {'$exists': True}
                    }
                },
                {
                    '$group': {
                        '_id': '$ip',
                        'protocols': {'$addToSet': '$protocol'},
                        'actions': {'$addToSet': '$action'},
                        'rules': {'$addToSet': '$rule'},  # Collect matched rules
                        'first_seen': {'$min': '$timestamp'},
                        'last_seen': {'$max': '$timestamp'},
                        'count': {'$sum': 1}
                    }
                }
            ]

            results = list(db.logs.aggregate(pipeline))
            
            print(f"  → Found {len(results)} unique IPs in database")

            # Convert to Hunterzzz format
            iocs = []
            for item in results:
                # Determine verdict based on count (simple heuristic)
                count = item.get('count', 0)
                if count > 10:
                    verdict = 'malicious'
                    score = 85
                elif count > 3:
                    verdict = 'suspicious'
                    score = 60
                else:
                    verdict = 'suspicious'
                    score = 40
                
                # Clean up rules (remove None/null)
                rules = [r for r in item.get('rules', []) if r]
                
                ioc = {
                    'type': 'ip',
                    'value': item['_id'],
                    'verdict': verdict,
                    'score': score,
                    'protocols': item.get('protocols', []),
                    'tags': self._generate_tags(item),
                    'rules': rules,  # Add matched Melissae rules
                    'geoip': {},
                    'asn': {}
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
        """
        Save API key to secure config file
        """
        # Use home directory if /etc not writable
        if os.access('/etc', os.W_OK):
            config_dir = '/etc/melissae'
        else:
            config_dir = os.path.expanduser('~/.melissae')
        config_file = os.path.join(config_dir, 'hunterzzz.conf')

        # Create directory if it doesn't exist
        os.makedirs(config_dir, mode=0o700, exist_ok=True)

        config = {
            'api_key': api_key,
            'ingest_endpoint': ingest_endpoint,
            'enrolled_at': datetime.now(timezone.utc).isoformat()
        }

        # Write with restrictive permissions
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)

        # Set file permissions to 600 (owner read/write only)
        os.chmod(config_file, 0o600)

    def _load_config(self) -> Optional[Dict]:
        """
        Load Hunterzzz configuration
        """
        # Try /etc first, fallback to home
        config_file = '/etc/melissae/hunterzzz.conf'
        if not os.path.exists(config_file):
            config_file = os.path.expanduser('~/.melissae/hunterzzz.conf')

        if not os.path.exists(config_file):
            return None

        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None


def main():
    parser = argparse.ArgumentParser(
        description='Melissae to Hunterzzz Integration'
    )

    parser.add_argument(
        'command',
        choices=['enroll', 'sync', 'test'],
        help='Command to execute'
    )

    parser.add_argument(
        '--hunterzzz-url',
        default=os.getenv('HUNTERZZZ_URL', 'https://hunterzzz.example.com'),
        help='Hunterzzz base URL'
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
    integration = HunterzzzIntegration(
        args.hunterzzz_url,
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
