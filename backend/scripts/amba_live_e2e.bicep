// Throwaway estate for the AMBA coverage live end-to-end test.
//
// Deploys a deliberately mixed set of alert rules so every detection path in
// app/amba/collector.py is exercised against REAL Azure Resource Graph payloads (not the
// synthetic fixtures the unit tests use):
//
//   present            static metric alert matching the baseline exactly
//   present            multi-resource metric alert scoped to the RESOURCE GROUP
//   present            dynamic-threshold metric alert
//   present            activity-log alert (Service Health, subscription scope)
//   present            activity-log alert (Administrative — Key Vault delete)
//   present            threshold honoured via an AMBA-ALZ `_amba-…-threshold-Override_` tag
//   misconfigured      rule disabled
//   misconfigured      rule with no action group
//   misconfigured      rule wired to an action group that has no receivers
//   misconfigured      rule whose threshold is far from the baseline
//   suppressed         rule muted by an unconditional alert processing rule
//   excluded           resource tagged MonitorDisable=true
//
// Everything is created inside one resource group which the harness deletes afterwards.

targetScope = 'resourceGroup'

@description('Deployment region for regional resources.')
param location string = resourceGroup().location

@description('Suffix that makes globally-scoped names unique.')
param suffix string

var storageName = 'ambae2e${suffix}'
var vaultName = 'amba-kv-${suffix}'

// ---------------------------------------------------------------- notification plumbing
resource goodActionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'amba-e2e-good-ag'
  location: 'global'
  properties: {
    groupShortName: 'ambaGood'
    enabled: true
    emailReceivers: [
      {
        name: 'oncall'
        emailAddress: 'amba-e2e@example.invalid'
        useCommonAlertSchema: true
      }
    ]
  }
}

// Deliberately receiver-less: a rule pointing here notifies nobody.
resource emptyActionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'amba-e2e-empty-ag'
  location: 'global'
  properties: {
    groupShortName: 'ambaEmpty'
    enabled: true
  }
}

// ---------------------------------------------------------------- monitored resources
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  tags: {
    // AMBA-ALZ per-resource override: the deployed Availability rule sits at 95, not the
    // baseline 100, and this tag is what makes that correct rather than drift.
    '_amba-Availability-threshold-Override_': '95'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: null
    accessPolicies: []
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'amba-e2e-pip'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// Tagged out of monitoring — the collector must list it as excluded, not as a pile of gaps.
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'amba-e2e-nsg'
  location: location
  tags: {
    MonitorDisable: 'true'
  }
  properties: {}
}

resource routeTable 'Microsoft.Network/routeTables@2023-11-01' = {
  name: 'amba-e2e-rt'
  location: location
  properties: {}
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'amba-e2e-law-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// ---------------------------------------------------------------- metric alerts
// PRESENT — matches the baseline exactly once the override tag on the storage account is
// applied (baseline says < 100, tag says 95, rule says 95).
resource storageAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-storage-availability'
  location: 'global'
  properties: {
    description: 'Storage availability below the tag-overridden threshold.'
    severity: 1
    enabled: true
    scopes: [ storage.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'availability'
          metricName: 'Availability'
          metricNamespace: 'Microsoft.Storage/storageAccounts'
          operator: 'LessThan'
          threshold: 95
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// PRESENT — multi-resource rule scoped to the RESOURCE GROUP. Before this work every
// vault under such a rule reported the alert as missing. (Azure only permits RG-scoped
// metric alerts for a subset of types; Key Vault is one, Storage is not.)
resource vaultHitMultiResource 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-kv-hits-multiresource'
  location: 'global'
  properties: {
    description: 'Multi-resource Key Vault API hit rule scoped to the whole resource group.'
    severity: 3
    enabled: true
    scopes: [ resourceGroup().id ]
    targetResourceType: 'Microsoft.KeyVault/vaults'
    targetResourceRegion: location
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'apihit'
          metricName: 'ServiceApiHit'
          metricNamespace: 'Microsoft.KeyVault/vaults'
          operator: 'GreaterThanOrEqual'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
  dependsOn: [ vault ]
}

// MISCONFIGURED — threshold far from the baseline (baseline > 1000ms, deployed at 60000ms).
// Uses a dimensionless baseline so the drift, not a dimension mismatch, is what is tested.
resource storageLatencyDrift 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-storage-latency-drift'
  location: 'global'
  properties: {
    description: 'E2E latency rule with a threshold well outside the baseline tolerance.'
    severity: 3
    enabled: true
    scopes: [ storage.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'e2elatency'
          metricName: 'SuccessE2ELatency'
          metricNamespace: 'Microsoft.Storage/storageAccounts'
          operator: 'GreaterThan'
          threshold: 60000
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// Dimension handling. The AMBA "Throttling" baseline requires BOTH a ResponseType and a
// FileShare dimension; this rule carries only ResponseType, so it must NOT satisfy it.
// (Azure rejects the FileShare dimension on an account-scoped Transactions rule, which is
// precisely why matching on dimensions rather than metric name alone matters.)
resource storageTransactionsDimension 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-storage-transactions-dimension'
  location: 'global'
  properties: {
    description: 'Transactions rule carrying a single ResponseType dimension.'
    severity: 3
    enabled: true
    scopes: [ storage.id ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'transactions'
          metricName: 'Transactions'
          metricNamespace: 'Microsoft.Storage/storageAccounts'
          operator: 'GreaterThanOrEqual'
          threshold: 1
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          dimensions: [
            {
              name: 'ResponseType'
              operator: 'Include'
              values: [ 'Success' ]
            }
          ]
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// PRESENT — dynamic threshold, which the baseline recommends for this metric.
resource vaultDynamic 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-kv-serviceapiresult-dynamic'
  location: 'global'
  properties: {
    description: 'Key Vault API results vs a dynamic threshold.'
    severity: 2
    enabled: true
    scopes: [ vault.id ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'apiresult'
          metricName: 'ServiceApiResult'
          metricNamespace: 'Microsoft.KeyVault/vaults'
          operator: 'GreaterThan'
          timeAggregation: 'Average'
          criterionType: 'DynamicThresholdCriterion'
          alertSensitivity: 'Medium'
          failingPeriods: {
            numberOfEvaluationPeriods: 4
            minFailingPeriodsToAlert: 4
          }
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// MISCONFIGURED — disabled.
resource vaultDisabled 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-kv-availability-disabled'
  location: 'global'
  properties: {
    description: 'Key Vault availability rule that is switched off.'
    severity: 1
    enabled: false
    scopes: [ vault.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'availability'
          metricName: 'Availability'
          metricNamespace: 'Microsoft.KeyVault/vaults'
          operator: 'LessThan'
          threshold: 90
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// MISCONFIGURED — no action group at all.
resource vaultNoActionGroup 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-kv-saturation-no-ag'
  location: 'global'
  properties: {
    description: 'Key Vault saturation rule that notifies nobody.'
    severity: 2
    enabled: true
    scopes: [ vault.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'saturation'
          metricName: 'SaturationShoebox'
          metricNamespace: 'Microsoft.KeyVault/vaults'
          operator: 'GreaterThan'
          threshold: 75
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: []
  }
}

// MISCONFIGURED — wired to an action group that has no receivers.
resource vaultEmptyActionGroup 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-kv-latency-empty-ag'
  location: 'global'
  properties: {
    description: 'Key Vault latency rule pointing at a receiver-less action group.'
    severity: 2
    enabled: true
    scopes: [ vault.id ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'latency'
          metricName: 'ServiceApiLatency'
          metricNamespace: 'Microsoft.KeyVault/vaults'
          operator: 'GreaterThan'
          threshold: 1000
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: emptyActionGroup.id } ]
  }
}

// SUPPRESSED — a healthy-looking rule that an alert processing rule silently mutes.
resource pipAvailability 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'amba-e2e-pip-vipavailability'
  location: 'global'
  properties: {
    description: 'Public IP data-path availability.'
    severity: 1
    enabled: true
    scopes: [ publicIp.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'vipavailability'
          metricName: 'VipAvailability'
          metricNamespace: 'Microsoft.Network/publicIPAddresses'
          operator: 'LessThan'
          threshold: 90
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [ { actionGroupId: goodActionGroup.id } ]
  }
}

// ---------------------------------------------------------------- alert processing rule
// Unconditional suppression scoped to the public IP: every alert on that resource is muted
// even though the rule above looks perfectly healthy.
resource suppression 'Microsoft.AlertsManagement/actionRules@2021-08-08' = {
  name: 'amba-e2e-suppress-pip'
  location: 'Global'
  properties: {
    description: 'Mutes every alert on the test public IP.'
    enabled: true
    scopes: [ publicIp.id ]
    actions: [
      {
        actionType: 'RemoveAllActionGroups'
      }
    ]
  }
}

// ---------------------------------------------------------------- activity log alerts
// PRESENT — Service Health incidents at subscription scope. Scored against the synthetic
// `microsoft.resources/subscriptions` row.
resource serviceHealthIncident 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: 'amba-e2e-servicehealth-incident'
  location: 'global'
  properties: {
    description: 'Service Health incident notifications.'
    enabled: true
    scopes: [ subscription().id ]
    condition: {
      allOf: [
        { field: 'category', equals: 'ServiceHealth' }
        { field: 'properties.incidentType', equals: 'Incident' }
      ]
    }
    actions: {
      actionGroups: [ { actionGroupId: goodActionGroup.id } ]
    }
  }
}

// PRESENT — Administrative activity log alert for Key Vault deletion.
resource vaultDeleteAlert 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: 'amba-e2e-kv-delete'
  location: 'global'
  properties: {
    description: 'Key Vault deletion notifications.'
    enabled: true
    scopes: [ subscription().id ]
    condition: {
      allOf: [
        { field: 'category', equals: 'Administrative' }
        { field: 'operationName', equals: 'Microsoft.KeyVault/vaults/delete' }
        { field: 'status', equals: 'Succeeded' }
      ]
    }
    actions: {
      actionGroups: [ { actionGroupId: goodActionGroup.id } ]
    }
  }
}

// ---------------------------------------------------------------- log search alert
// Exists so the harness can assert the collector extracts a query signature (primary table
// plus the discriminating Name/CounterName operands) from a REAL scheduledQueryRules payload.
resource logSearchRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'amba-e2e-log-freespace'
  location: location
  properties: {
    description: 'AMBA-shaped guest OS free disk space log alert.'
    severity: 2
    enabled: true
    scopes: [ workspace.id ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    criteria: {
      allOf: [
        {
          query: 'InsightsMetrics\n| where Origin == "vm.azm.ms"\n| where Namespace == "LogicalDisk" and Name == "FreeSpacePercentage"\n| summarize AggregatedValue = avg(Val) by bin(TimeGenerated,15m), Computer, _ResourceId'
          operator: 'LessThan'
          threshold: 10
          timeAggregation: 'Average'
          metricMeasureColumn: 'AggregatedValue'
          resourceIdColumn: '_ResourceId'
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [ goodActionGroup.id ]
    }
  }
}

output storageId string = storage.id
output vaultId string = vault.id
output vaultName string = vaultName
output publicIpId string = publicIp.id
output nsgId string = nsg.id
output routeTableId string = routeTable.id
output workspaceId string = workspace.id
output goodActionGroupId string = goodActionGroup.id
output emptyActionGroupId string = emptyActionGroup.id
