"""Backup cost: live retail pricing, Cost Management shaping, allocation, and variance."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.api import backup_manager as api
from app.backup_manager import cost, costmgmt, pricing

# A faithful slice of what the live Retail Prices API returns for serviceName 'Backup',
# including the Reservation rows that must be excluded.
RETAIL_BACKUP = [
    {"meterName": "Azure VM Protected Instance", "retailPrice": 8.775779, "type": "Consumption"},
    {"meterName": "Azure Files Protected Instance", "retailPrice": 4.387889, "type": "Consumption"},
    {"meterName": "Azure Kubernetes Protected Instance", "retailPrice": 10.530935, "type": "Consumption"},
    {"meterName": "PostgreSQL Protected Instance", "retailPrice": 6.581834, "type": "Consumption"},
    {"meterName": "Azure Blob Protected Instance", "retailPrice": 11.408513, "type": "Consumption"},
    {"meterName": "SQL Server in Azure VM Protected Instance", "retailPrice": 28.521281, "type": "Consumption"},
    {"meterName": "SQL Server in Azure VM Snapshot Instance", "retailPrice": 31.373409, "type": "Consumption"},
    {"meterName": "Standard LRS Data Stored", "retailPrice": 0.019658, "type": "Consumption"},
    {"meterName": "Standard ZRS Data Stored", "retailPrice": 0.024572, "type": "Consumption"},
    {"meterName": "Standard GRS Data Stored", "retailPrice": 0.039315, "type": "Consumption"},
    {"meterName": "Standard RA-GRS Data Stored", "retailPrice": 0.049934, "type": "Consumption"},
    {"meterName": "Archive LRS Data Stored", "retailPrice": 0.002106, "type": "Consumption"},
    {"meterName": "Azure Files Vaulted GRS Data Stored", "retailPrice": 0.086705, "type": "Consumption"},
    {"meterName": "Azure Files Vaulted LRS Data Stored", "retailPrice": 0.046775, "type": "Consumption"},
    # Reservation rows price a whole 100 TB / 1 PB term. Including them would inflate an
    # estimate by roughly six orders of magnitude.
    {"meterName": "GRS Data Stored", "retailPrice": 415550.680123, "type": "Reservation"},
    {"meterName": "LRS Data Stored", "retailPrice": 207775.340061, "type": "Reservation"},
]
RETAIL_ASR = [
    {"meterName": "VM Replicated to Azure", "retailPrice": 21.939447, "type": "Consumption"},
    {"meterName": "VM Replicated to System Center", "retailPrice": 14.041246, "type": "Consumption"},
]

VAULT = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/rsv"


@pytest.fixture
def card() -> dict:
    return pricing.build_rate_card(RETAIL_BACKUP, RETAIL_ASR, region="westeurope", currency="EUR")


def _estate(*instances: dict, redundancy: str = "GeoRedundant", replication: int = 0) -> dict:
    return {
        "vaults": [{
            "id": VAULT, "name": "rsv", "kind": "recovery_services", "location": "westeurope",
            "redundancy": redundancy, "instance_count": len(instances), "empty": not instances,
        }],
        "instances": list(instances),
        "replication": [{"id": f"r{i}"} for i in range(replication)],
        "policies": [],
    }


def _instance(instance_id: str, name: str, datasource_type: str, **overrides) -> dict:
    row = {
        "id": instance_id, "friendly_name": name, "datasource_type": datasource_type,
        "backup_management_type": "", "vault_id": VAULT, "vault_name": "rsv",
        "datasource_id": f"/ds/{name}", "orphaned": False, "retain_data_only": False,
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- rate card
def test_rate_card_excludes_reservation_rows(card) -> None:
    """A Reservation row prices a whole 100 TB term; mixing it in destroys the estimate."""
    assert card["storage_gb_month"]["grs"] == pytest.approx(0.039315)
    assert card["storage_gb_month"]["lrs"] == pytest.approx(0.019658)
    assert all(rate < 1 for rate in card["storage_gb_month"].values())


def test_rate_card_prices_each_datasource_type_separately(card) -> None:
    """Azure Backup charges a flat monthly rate per datasource type, not a size tier."""
    meters = card["instance_meters"]
    assert meters["azure vm"] == pytest.approx(8.775779)
    assert meters["azure files"] == pytest.approx(4.387889)
    assert meters["sql server in azure vm"] == pytest.approx(28.521281)
    assert meters["azure vm"] != meters["azure files"]


def test_protected_instance_meter_wins_over_snapshot_instance(card) -> None:
    assert card["instance_meters"]["sql server in azure vm"] == pytest.approx(28.521281)


def test_rate_card_captures_files_specific_storage_and_asr(card) -> None:
    assert card["files_storage_gb_month"]["grs"] == pytest.approx(0.086705)
    assert card["files_storage_gb_month"]["grs"] > card["storage_gb_month"]["grs"]
    assert card["site_recovery_instance_month"] == pytest.approx(21.939447)


@pytest.mark.parametrize(
    "datasource,management,expected_key",
    [
        ("VM", "AzureIaasVM", "azure vm"),
        ("AzureFileShare", "", "azure files"),
        ("Microsoft.ContainerService/managedClusters", "", "azure kubernetes"),
        ("Microsoft.DBforPostgreSQL/flexibleServers", "", "postgresql"),
    ],
)
def test_instance_rate_lookup(card, datasource, management, expected_key) -> None:
    rate, key = pricing.instance_rate(card, datasource, management)
    assert key == expected_key
    assert rate and rate > 0


def test_managed_disks_have_no_protected_instance_meter(card) -> None:
    """Azure Disk Backup is snapshot-billed outside the Backup service — reported, not faked."""
    rate, key = pricing.instance_rate(card, "Microsoft.Compute/disks")
    assert key == "no_instance_meter"
    assert rate is None


def test_storage_rate_maps_redundancy_and_files_variant(card) -> None:
    assert pricing.storage_rate(card, "GeoRedundant") == pytest.approx(0.039315)
    assert pricing.storage_rate(card, "LocallyRedundant") == pytest.approx(0.019658)
    assert pricing.storage_rate(card, "ZoneRedundant") == pytest.approx(0.024572)
    assert pricing.storage_rate(card, "GeoRedundant", files=True) == pytest.approx(0.086705)


def test_unavailable_rate_card_degrades_to_the_reference(card) -> None:
    fallback = cost.reference_rate_card()
    assert fallback["source"] == "reference"
    assert fallback["fallback_instance_rate"] > 0


# --------------------------------------------------------------------------- estimate
def test_estimate_uses_per_datasource_rates(card) -> None:
    estate = _estate(
        _instance("i-vm", "vm1", "VM", backup_management_type="AzureIaasVM"),
        _instance("i-files", "share1", "AzureFileShare"),
    )
    result = cost.estimate(estate, rate_card=card, storage_by_instance={"i-vm": 100.0, "i-files": 100.0})
    assert result["currency"] == "EUR"
    assert result["rate_source"] == "azure_retail_prices"
    by_name = {row["name"]: row for row in result["top_rows"]}
    assert by_name["vm1"]["instance_cost"] == pytest.approx(8.78, abs=0.01)
    assert by_name["share1"]["instance_cost"] == pytest.approx(4.39, abs=0.01)
    # Azure Files vault storage is priced on its own, more expensive meter.
    assert by_name["share1"]["storage_cost"] > by_name["vm1"]["storage_cost"]
    assert result["confidence"] == "measured"


def test_estimate_flags_a_datasource_it_cannot_price(card) -> None:
    estate = _estate(_instance("i-disk", "disk1", "Microsoft.Compute/disks"))
    result = cost.estimate(estate, rate_card=card)
    row = result["top_rows"][0]
    assert row["instance_cost"] == 0.0
    assert "Snapshot-billed" in row["note"]


def test_estimate_prices_site_recovery_from_the_live_meter(card) -> None:
    estate = _estate(_instance("i-vm", "vm1", "VM"), replication=3)
    result = cost.estimate(estate, rate_card=card)
    assert result["site_recovery_cost"] == pytest.approx(3 * 21.939447, abs=0.01)


# --------------------------------------------------------------------------- allocation
def _actuals(by_vault: dict[str, float], **overrides) -> dict:
    row = {
        "available": True, "by_vault": by_vault, "by_meter": {}, "currency": "EUR",
        "total": round(sum(by_vault.values()), 2), "partial_period": False,
        "period": {"from": "", "to": "", "partial": "false"}, "reason": "",
    }
    row.update(overrides)
    return row


def test_allocation_reconciles_exactly_to_the_vault_total(card) -> None:
    """Per-item figures must sum back to the invoice, or the view is quietly lying."""
    estate = _estate(
        _instance("a", "a", "VM"), _instance("b", "b", "VM"), _instance("c", "c", "VM"),
    )
    actuals = _actuals({VAULT.lower(): 100.0})
    result = cost.allocate(estate, actuals, storage_by_instance={"a": 1.0, "b": 1.0, "c": 1.0})
    assert len(result["rows"]) == 3
    assert result["allocated_total"] == pytest.approx(100.0, abs=0.001)


def test_allocation_absorbs_rounding_drift(card) -> None:
    """Three equal shares of 10.00 are 3.33 each; the lost cent must land somewhere."""
    estate = _estate(_instance("a", "a", "VM"), _instance("b", "b", "VM"), _instance("c", "c", "VM"))
    result = cost.allocate(estate, _actuals({VAULT.lower(): 10.0}),
                           storage_by_instance={"a": 1.0, "b": 1.0, "c": 1.0})
    assert result["allocated_total"] == pytest.approx(10.0, abs=0.001)


def test_allocation_weights_prefer_measured_consumption(card) -> None:
    estate = _estate(_instance("big", "big", "VM"), _instance("small", "small", "VM"))
    result = cost.allocate(
        estate, _actuals({VAULT.lower(): 90.0}),
        storage_by_instance={"big": 800.0, "small": 100.0},
    )
    assert {r["weight_basis"] for r in result["rows"]} == {"consumed_gb"}
    by_name = {r["name"]: r["allocated_cost"] for r in result["rows"]}
    assert by_name["big"] == pytest.approx(80.0, abs=0.01)
    assert by_name["small"] == pytest.approx(10.0, abs=0.01)


def test_allocation_falls_back_to_estimated_cost_then_equal_shares(card) -> None:
    estate = _estate(_instance("a", "a", "VM"), _instance("b", "b", "VM"))
    weighted = cost.allocate(
        estate, _actuals({VAULT.lower(): 30.0}),
        estimate_rows=[{"instance_id": "a", "monthly_cost": 20.0},
                       {"instance_id": "b", "monthly_cost": 10.0}],
    )
    assert {r["weight_basis"] for r in weighted["rows"]} == {"estimated_cost"}
    assert {r["name"]: r["allocated_cost"] for r in weighted["rows"]}["a"] == pytest.approx(20.0, abs=0.01)

    equal = cost.allocate(estate, _actuals({VAULT.lower(): 30.0}))
    assert {r["weight_basis"] for r in equal["rows"]} == {"equal"}
    assert all(r["allocated_cost"] == pytest.approx(15.0, abs=0.01) for r in equal["rows"])


def test_spend_on_an_out_of_scope_vault_is_reported_not_dropped(card) -> None:
    """Silently discarding real spend would make the total disagree with the bill."""
    estate = _estate(_instance("a", "a", "VM"))
    actuals = _actuals({VAULT.lower(): 40.0, "/subscriptions/s1/…/vaults/elsewhere": 25.0})
    result = cost.allocate(estate, actuals)
    assert result["allocated_total"] == pytest.approx(40.0, abs=0.01)
    assert result["unattributed_total"] == pytest.approx(25.0, abs=0.01)
    assert result["vaults_unattributed"] == 1


def test_allocation_states_that_azure_attributes_cost_to_the_vault(card) -> None:
    result = cost.allocate(_estate(_instance("a", "a", "VM")), _actuals({VAULT.lower(): 5.0}))
    assert "vault" in result["note"].lower()


# --------------------------------------------------------------------------- variance
def test_variance_reports_delta_when_comparable(card) -> None:
    estimate = {"monthly_total": 100.0, "currency": "EUR"}
    result = cost.variance(estimate, _actuals({VAULT.lower(): 80.0}))
    assert result["comparable"] is True
    assert result["delta"] == pytest.approx(-20.0)
    assert result["delta_pct"] == pytest.approx(-20.0)
    assert result["reason"] == ""


def test_variance_refuses_to_compare_a_partial_month(card) -> None:
    estimate = {"monthly_total": 100.0, "currency": "EUR"}
    result = cost.variance(estimate, _actuals({VAULT.lower(): 30.0}, partial_period=True))
    assert result["comparable"] is False
    assert "Month-to-date" in result["reason"]


def test_variance_refuses_to_compare_across_currencies(card) -> None:
    estimate = {"monthly_total": 100.0, "currency": "USD"}
    result = cost.variance(estimate, _actuals({VAULT.lower(): 80.0}))
    assert result["comparable"] is False
    assert "USD" in result["reason"] and "EUR" in result["reason"]


def test_variance_explains_unavailable_actuals(card) -> None:
    estimate = {"monthly_total": 100.0, "currency": "EUR"}
    unavailable = {"available": False, "currency": "", "total": 0.0,
                   "reason": "Cost Management access denied.", "partial_period": False}
    result = cost.variance(estimate, unavailable)
    assert result["comparable"] is False
    assert "denied" in result["reason"]


# --------------------------------------------------------------------------- waste
def test_waste_prices_findings_from_real_money_when_available(card) -> None:
    estate = _estate(_instance("orphan", "orphan", "VM", orphaned=True))
    estimated = cost.waste(estate, rate_card=card)
    allocated = cost.waste(estate, rate_card=card, cost_by_instance={"orphan": 42.0})
    assert estimated["basis"] == "estimated"
    assert allocated["basis"] == "actual"
    assert allocated["findings"][0]["monthly_cost"] == pytest.approx(42.0)


def test_waste_guidance_never_suggests_an_operation_the_module_refuses(card) -> None:
    estate = _estate(_instance("orphan", "orphan", "VM", orphaned=True))
    finding = cost.waste(estate, rate_card=card)["findings"][0]
    assert "portal" in finding["action"].lower()


# --------------------------------------------------------------------------- cost management
def test_month_period_returns_a_complete_previous_month() -> None:
    period = costmgmt.month_period(1)
    assert period["partial"] == "false"
    start = datetime.fromisoformat(period["from"])
    end = datetime.fromisoformat(period["to"])
    assert start.day == 1
    assert end > start
    assert (end - start).days <= 31


def test_month_period_zero_is_month_to_date_and_says_so() -> None:
    period = costmgmt.month_period(0)
    assert period["partial"] == "true"
    assert datetime.fromisoformat(period["from"]).day == 1
    assert datetime.fromisoformat(period["from"]) <= datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_actuals_without_subscriptions_fails_closed_with_a_reason() -> None:
    result = await costmgmt.backup_actuals({"id": "c1"}, [])
    assert result["available"] is False
    assert result["reason"]


# --------------------------------------------------------------------------- report matching
def test_report_storage_matching_drops_ambiguous_names() -> None:
    """A wrong weight silently misallocates real money, so an ambiguous match is discarded."""
    estate = {"instances": [
        {"id": "i-1", "friendly_name": "web"},
        {"id": "i-2", "friendly_name": "unique-db"},
    ]}
    matched = api._match_report_storage(estate, {
        "web-prod-01": 10.0,      # two rows contain "web" -> ambiguous, dropped
        "web-prod-02": 20.0,
        "unique-db-instance": 30.0,
    })
    assert "i-1" not in matched
    assert matched["i-2"] == pytest.approx(30.0)


def test_price_region_follows_where_the_vaults_actually_live() -> None:
    estate = {"vaults": [
        {"location": "westeurope"}, {"location": "westeurope"}, {"location": "eastus"},
    ]}
    assert api._price_region(estate, {}) == "westeurope"
    assert api._price_region({"vaults": []}, {}) in ("eastus", "")


# --------------------------------------------------------------------------- billing currency
def test_known_currency_reads_the_billing_currency_from_cache(monkeypatch) -> None:
    """The overview must not quote USD while the Cost tab quotes the real billing currency."""
    monkeypatch.setattr(costmgmt, "_read_cache", lambda: {
        "t1|c1|sub-a|1|AmortizedCost|True": {"cached_at": 100.0, "result": {"currency": "USD"}},
        "t1|c1|sub-a,sub-b|1|AmortizedCost|True": {"cached_at": 200.0, "result": {"currency": "CAD"}},
        "t1|c2|sub-z|1|AmortizedCost|True": {"cached_at": 300.0, "result": {"currency": "EUR"}},
    })
    # Newest entry for this connection wins; another connection's currency is never borrowed.
    assert costmgmt.known_currency({"id": "c1"}, tenant_id="t1") == "CAD"
    assert costmgmt.known_currency({"id": "c2"}, tenant_id="t1") == "EUR"


def test_known_currency_is_empty_when_nothing_is_cached(monkeypatch) -> None:
    monkeypatch.setattr(costmgmt, "_read_cache", lambda: {})
    assert costmgmt.known_currency({"id": "c1"}, tenant_id="t1") == ""


def test_known_currency_ignores_another_tenant(monkeypatch) -> None:
    monkeypatch.setattr(costmgmt, "_read_cache", lambda: {
        "other|c1|sub-a|1|AmortizedCost|True": {"cached_at": 100.0, "result": {"currency": "CAD"}},
    })
    assert costmgmt.known_currency({"id": "c1"}, tenant_id="t1") == ""
