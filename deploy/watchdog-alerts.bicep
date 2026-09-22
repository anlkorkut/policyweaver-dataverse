targetScope = 'resourceGroup'

param location string = 'swedencentral'
param namePrefix string = 'pw-watchdog'
param logWorkspaceName string = 'pw-watchdog-logs'
param jobName string = 'pw-watchdog-job'
@description('Actual EnvironmentName_s value observed in this workspace; this is not the ARM environment resource name.')
param environmentLogName string

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logWorkspaceName
}

// Column names were verified against the actual workspace getschema output.
// This template deliberately has no notification recipients or action groups.
var jobLogs = format('''
ContainerAppConsoleLogs_CL
| where ContainerJobName_s == '{0}' and EnvironmentName_s == '{1}' and ContainerName_s == 'watchdog'
| extend event = parse_json(Log_s)
''', jobName, environmentLogName)

resource critical 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${namePrefix}-critical'
  location: location
  kind: 'LogAlert'
  properties: {
    description: 'Portal-only alert for a structured PolicyWeaver watchdog critical result. No incident notifications configured.'
    displayName: 'PolicyWeaver watchdog critical result'
    enabled: true
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [logs.id]
    autoMitigate: true
    skipQueryValidation: false
    actions: { actionGroups: [] }
    criteria: {
      allOf: [{
        query: '${jobLogs}\n| where event.critical == true'
        timeAggregation: 'Count'
        operator: 'GreaterThan'
        threshold: 0
        failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
      }]
    }
  }
}

resource heartbeat 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${namePrefix}-missing-heartbeat'
  location: location
  kind: 'LogAlert'
  properties: {
    description: 'Portal-only alert when no healthy mutating-mode watchdog result arrived within 15 minutes. No incident notifications configured.'
    displayName: 'PolicyWeaver watchdog missing healthy heartbeat'
    enabled: true
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [logs.id]
    autoMitigate: true
    skipQueryValidation: false
    actions: { actionGroups: [] }
    criteria: {
      allOf: [{
        query: '${jobLogs}\n| where event.status == "ok" and event.critical == false and event.inspect_only == false\n| where todatetime(event.inspected_at) between (ago(15m) .. now())\n| summarize HealthyCount = count()'
        metricMeasureColumn: 'HealthyCount'
        timeAggregation: 'Maximum'
        operator: 'LessThan'
        threshold: 1
        failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
      }]
    }
  }
}

output criticalAlertId string = critical.id
output missingHeartbeatAlertId string = heartbeat.id
