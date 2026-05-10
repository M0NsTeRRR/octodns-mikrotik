import base64
import json
from importlib.metadata import version

import pytest
import responses
from octodns.record import Record
from octodns.zone import Zone
from responses import matchers

from octodns_mikrotik import (
    MikroTikClientBadRequest,
    MikroTikClientForbidden,
    MikroTikClientNotFound,
    MikroTikClientUnauthorized,
    MikroTikProvider,
)

HOST = "router.example.test"
USER = "user"
PASSWORD = "password"


def test_http_error():
    zone_name = "example.test."
    provider = MikroTikProvider("mikrotik", HOST, USER, PASSWORD)

    # 400
    with responses.RequestsMock() as mock:
        mock.get(f"https://{HOST}:443/rest/ip/dns/static", status=400)

        with pytest.raises(MikroTikClientBadRequest):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 401
    with responses.RequestsMock() as mock:
        mock.get(f"https://{HOST}:443/rest/ip/dns/static", status=401)

        with pytest.raises(MikroTikClientUnauthorized):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 403
    with responses.RequestsMock() as mock:
        mock.get(f"https://{HOST}:443/rest/ip/dns/static", status=403)

        with pytest.raises(MikroTikClientForbidden):
            zone = Zone(zone_name, [])
            provider.populate(zone)

    # 404
    with responses.RequestsMock() as mock:
        mock.get(f"https://{HOST}:443/rest/ip/dns/static", status=404)

        with pytest.raises(MikroTikClientNotFound):
            zone = Zone(zone_name, [])
            provider.populate(zone)


def test_populate_empty_zone():
    zone_name = "example.test."
    auth = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    provider = MikroTikProvider("mikrotik", "router.example.test", USER, PASSWORD)

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/empty_example.test.json") as f:
            mock.get(
                f"https://{HOST}:443/rest/ip/dns/static",
                status=200,
                headers={
                    "Authorization": f"Basic {auth}",
                    "User-Agent": f"octodns/{version('octodns')} octodns-mikrotik/{version('octodns-mikrotik')}",
                },
                json=json.loads(f.read()),
            )

        zone = Zone(zone_name, [])
        assert not provider.populate(zone)
        assert 0 == len(zone.records)
        assert set() == zone.records


def test_populate_zone():
    zone_name = "example.test."
    provider = MikroTikProvider("mikrotik", HOST, USER, PASSWORD)

    wanted = Zone(zone_name, [])
    wanted.add_record(
        Record.new(
            wanted,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns2.example2.test."],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1", "192.0.2.4"]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test",
            {"ttl": 300, "type": "AAAA", "value": ["2001:db8::3", "2001:db8::7"]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test2",
            {"ttl": 3600, "type": "CNAME", "value": "test.example2.test."},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "mail",
            {
                "ttl": 3600,
                "type": "MX",
                "value": [
                    {
                        "priority": 10,
                        "exchange": "mail.example.test.",
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "test6",
            {"ttl": 3600, "type": "NS", "value": ["test.example2.test."]},
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "_imap._tcp",
            {
                "ttl": 3600,
                "type": "SRV",
                "value": [
                    {
                        "priority": 10,
                        "weight": 0,
                        "port": 8000,
                        "target": "test.example.test.",
                    }
                ],
            },
        )
    )
    wanted.add_record(
        Record.new(
            wanted,
            "_dmarc",
            {
                "ttl": 3600,
                "type": "TXT",
                "value": [
                    "v=DMARC1\\; p=reject\\; aspf=s\\; adkim=s\\; rua=mailto:security@example.test\\; ruf=mailto:security@example.test\\;"
                ],
            },
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/get_example.test.json") as f:
            mock.get(
                f"https://{HOST}:443/rest/ip/dns/static",
                status=200,
                json=json.loads(f.read()),
            )

        expected = Zone(zone_name, [])
        assert provider.populate(expected)
        assert 8 == len(expected.records)
        assert expected.records == wanted.records


def test_apply_full_zone():
    zone_name = "example.test."
    provider = MikroTikProvider("mikrotik", HOST, USER, PASSWORD)

    expected = Zone(zone_name, [])
    expected.add_record(
        Record.new(
            expected,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns2.example2.test."],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1", "192.0.2.4"]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 300, "type": "AAAA", "value": ["2001:db8::3", "2001:db8::7"]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test2",
            {"ttl": 3600, "type": "CNAME", "value": "test.example.test."},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "mail",
            {
                "ttl": 3600,
                "type": "MX",
                "value": [
                    {
                        "priority": 10,
                        "exchange": "mail.example.test.",
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test6",
            {"ttl": 3600, "type": "NS", "value": ["test.example.test."]},
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_imap._tcp",
            {
                "ttl": 3600,
                "type": "SRV",
                "value": [
                    {
                        "priority": 10,
                        "weight": 0,
                        "port": 8000,
                        "target": "test.example.test.",
                    }
                ],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_dmarc",
            {
                "ttl": 3600,
                "type": "TXT",
                "value": [
                    "v=DMARC1\\; p=reject\\; aspf=s\\; adkim=s\\; rua=mailto:security@example.test\\; ruf=mailto:security@example.test\\;"
                ],
            },
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/empty_example.test.json") as f:
            mock.get(
                f"https://{HOST}:443/rest/ip/dns/static",
                status=200,
                json=json.loads(f.read()),
            )

        with open("tests/fixtures/put_example.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.put(
                    f"https://{HOST}:443/rest/ip/dns/static",
                    status=201,
                    match=[matchers.json_params_matcher(data)],
                    json={},
                )

        plan = provider.plan(expected)
        assert 8 == len(plan.changes)
        apply = provider.apply(plan)
        assert 8 == apply
        assert not plan.exists


def test_apply_update_zone():
    zone_name = "example2.test."
    provider = MikroTikProvider("mikrotik", HOST, USER, PASSWORD)

    expected = Zone(zone_name, [])
    expected.add_record(
        Record.new(
            expected,
            "",
            {
                "ttl": 3600,
                "type": "NS",
                "value": ["ns1.example2.test.", "ns3.example2.test."],
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "_imap._tcp",
            {
                "type": "SRV",
                "ttl": 3600,
                "value": {
                    "priority": "10",
                    "weight": "0",
                    "port": "8001",
                    "target": "test.example2.test.",
                },
            },
        )
    )
    expected.add_record(
        Record.new(
            expected,
            "test",
            {"ttl": 3600, "type": "A", "value": ["192.0.2.1"]},
        )
    )

    with responses.RequestsMock() as mock:
        with open("tests/fixtures/get_example2.test.json") as f:
            mock.get(
                f"https://{HOST}:443/rest/ip/dns/static",
                status=200,
                json=json.loads(f.read()),
            )

        with open("tests/fixtures/put_example2.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.put(
                    f"https://{HOST}:443/rest/ip/dns/static",
                    status=201,
                    match=[matchers.json_params_matcher(data)],
                    json={},
                )

        with open("tests/fixtures/delete_example2.test.json") as f:
            datas = json.loads(f.read())
            for data in datas:
                mock.delete(f"https://{HOST}:443/rest/ip/dns/static/{data}", status=200)

        plan = provider.plan(expected)
        assert 4 == len(plan.changes)
        apply = provider.apply(plan)
        assert 4 == apply
        assert plan.exists
