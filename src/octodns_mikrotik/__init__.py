import logging
from collections import defaultdict
from importlib.metadata import version
from typing import Any, Iterator, Literal

from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider, Plan
from octodns.record import (
    AaaaRecord,
    ARecord,
    Change,
    CnameRecord,
    MxRecord,
    NsRecord,
    Record,
    SrvRecord,
    TxtRecord,
)
from octodns.zone import Zone
from requests import Session
from requests.auth import HTTPBasicAuth


class MikrotikClientException(ProviderException):
    pass


class MikrotikProviderException(ProviderException):
    pass


class MikrotikClientBadRequest(MikrotikClientException):
    def __init__(self):
        super().__init__("Bad request")


class MikrotikClientUnauthorized(MikrotikClientException):
    def __init__(self):
        super().__init__("Unauthorized")


class MikrotikClientForbidden(MikrotikClientException):
    def __init__(self):
        super().__init__("Forbidden")


class MikrotikClientNotFound(MikrotikClientException):
    def __init__(self):
        super().__init__("Not found")


_HTTP_SCHEME = Literal["http", "https"]


class MikrotikClient(object):
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        scheme: _HTTP_SCHEME = "http",
        ssl_verify: bool = True,
    ):
        session = Session()
        session.headers.update(
            {
                "User-Agent": f"octodns/{version('octodns')} octodns-mikrotik/{version(__package__)}",  # type: ignore
            }
        )
        session.auth = HTTPBasicAuth(user, password)
        session.verify = ssl_verify
        self._session = session
        self.endpoint = f"{scheme}://{host}:{port:d}/rest"

    def _request(self, method: str, path: str, params=None, data=None) -> Any:
        url = f"{self.endpoint}{path}"
        r = self._session.request(method, url, params=params, json=data)

        if r.status_code == 400:
            raise MikrotikClientBadRequest()
        elif r.status_code == 401:
            raise MikrotikClientUnauthorized()
        elif r.status_code == 403:
            raise MikrotikClientForbidden()
        elif r.status_code == 404:
            raise MikrotikClientNotFound()

        if method != "DELETE":
            return r.json()

    def get_records(self) -> list[dict[str, str]]:
        path = "/ip/dns/static"
        return self._request("GET", path)

    def put_record(self, data):
        path = "/ip/dns/static"
        self._request("PUT", path, data=data)

    def delete_record(self, id: str):
        path = f"/ip/dns/static/{id}"
        self._request("DELETE", path)


class MikrotikProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS_POOL_VALUE_STATUS = False
    SUPPORTS = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "SRV",
        "TXT",
    )

    def __init__(
        self,
        id: str,
        host: str,
        port: int,
        user: str,
        password: str,
        scheme: _HTTP_SCHEME = "http",
        ssl_verify: bool = True,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f"MikrotikProvider[{id}]")
        self.log.debug("__init__: id=%s, token=***", id)
        super().__init__(id, *args, **kwargs)
        self._client = MikrotikClient(host, port, user, password, scheme, ssl_verify)

        self._records: list[dict] = []

    def _get_fqdn(self, name: str) -> str:
        return name if name.endswith(".") else f"{name}."

    def _get_ttl(self, ttl: str) -> int:
        _ttl = int(ttl[:-1])

        if ttl.endswith("w"):
            _ttl = _ttl * 7 * 24 * 60 * 60
        elif ttl.endswith("d"):
            _ttl = _ttl * 24 * 60 * 60
        elif ttl.endswith("h"):
            _ttl = _ttl * 60 * 60
        elif ttl.endswith("m"):
            _ttl = _ttl * 60
        elif ttl.endswith("s"):
            pass
        else:
            ValueError(f"Mikrotik TTL suffix {ttl[-1]} not handled")

        return _ttl

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> bool:
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))

        for record in self.records():
            # ignore record not in the current zone
            if not self._get_fqdn(record["name"]).endswith(zone.name):
                continue

            _name = self._get_fqdn(record["name"]).rstrip(zone.name)
            _type = record["type"]

            if _type not in self.SUPPORTS:
                self.log.warning(
                    f"populate: skipping unsupported {_type} {_name}.{zone} record"
                )
                continue
            values[_name][_type].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f"_data_for_{_type}")

                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = any(
            zone.name.endswith(self._get_fqdn(key["name"])) for key in self.records()
        )
        self.log.info(
            "populate:   found %s records, exists=%s",
            len(zone.records) - before,
            exists,
        )
        return exists

    def records(self) -> list[Any]:
        if len(self._records) == 0:
            self._records = self._client.get_records()

        return self._records

    def _data_for_multiple(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "values": [record["address"] for record in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_CNAME(self, _type, records):
        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "value": self._get_fqdn(records[0]["cname"]),
        }

    def _data_for_MX(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            values.append(
                {
                    "priority": int(record["mx-priority"]),
                    "exchange": self._get_fqdn(record["mx-exchange"]),
                }
            )

        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "values": values,
        }

    def _data_for_NS(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "values": [self._get_fqdn(record["ns"]) for record in records],
        }

    def _data_for_SRV(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        values = []
        for record in records:
            values.append(
                {
                    "priority": int(record["srv-priority"]),
                    "weight": int(record["srv-weight"]),
                    "port": int(record["srv-port"]),
                    "target": self._get_fqdn(record["srv-target"]),
                }
            )

        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "values": values,
        }

    def _data_for_TXT(
        self, _type: str, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "ttl": self._get_ttl(records[0]["ttl"]),
            "type": _type,
            "values": [record["text"] for record in records],
        }

    def _params_for_ip(self, record: ARecord | AaaaRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": record.fqdn,
                "address": value,
                "ttl": record.ttl,
                "type": record._type,
            }

    _params_for_A = _params_for_ip
    _params_for_AAAA = _params_for_ip

    def _params_for_CNAME(self, record: CnameRecord) -> Iterator[dict[str, Any]]:
        yield {
            "name": record.fqdn,
            "cname": record.value,
            "ttl": record.ttl,
            "type": record._type,
        }

    def _params_for_MX(self, record: MxRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": record.fqdn,
                "mx-exchange": value.exchange,
                "mx-preference": value.preference,
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_NS(self, record: NsRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": record.fqdn,
                "cname": value,
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_SRV(self, record: SrvRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": record.fqdn,
                "srv-port": value.port,
                "srv-target": value.target,
                "srv-priority": value.priority,
                "srv-weight": value.weight,
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_TXT(self, record: TxtRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": record.fqdn,
                "text": value,
                "ttl": record.ttl,
                "type": record._type,
            }

    def _apply_create(self, changes: Change):
        new = changes.new
        params_for = getattr(self, f"_params_for_{new._type}")

        for param in params_for(new):
            if param["name"] == ".":
                param["name"] = ""

            self._client.put_record(param)

    def _apply_delete(self, changes: Change):
        existing = changes.existing

        for record in self.records():
            if (
                existing.fqdn == self._get_fqdn(record["name"])
                and existing._type == record["type"]
            ):
                self._client.delete_record(record[".id"])

    def _apply_update(self, changes: Change):
        self._apply_delete(changes)
        self._apply_create(changes)

    def _apply(self, plan: Plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        for change in changes:
            class_name = change.__class__.__name__.lower()
            self.log.info(change)
            getattr(self, f"_apply_{class_name}")(change)
