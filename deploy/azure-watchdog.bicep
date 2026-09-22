targetScope = 'resourceGroup'

@description('Prefix for dedicated watchdog Azure resources; lowercase letters, numbers and hyphens.')
@maxLength(24)
param namePrefix string = 'pw-watchdog'

param location string = 'swedencentral'

@description('Existing ACR name. This template does not create a registry or publish an image.')
param registryName string

param registryResourceGroup string = resourceGroup().name

@description('Complete ACR image reference. Use an immutable @sha256 digest after build and scanning.')
param containerImage string

@description('Adapter configuration after provisioning, including every serving_items entry. Authentication is replaced with this job managed identity.')
@secure()
param watchdogConfig object

@description('Use ABAC repository permissions when the existing registry is configured for AbacRepositoryPermissions.')
param registryUsesAbac bool = false

@description('Only this repository can be pulled when registryUsesAbac is true.')
param repositoryName string = 'policyweaver/watchdog'

@description('Enable the five-minute schedule only after managed-identity permissions and alerting are qualified.')
param enableSchedule bool = false

@description('Enable expired-role withdrawal only after an inspect run and controlled expiry test. False is read-only.')
param enableWithdrawal bool = false

var registryPullRoleDefinitionId = registryUsesAbac ? 'b93aa761-3e63-49ed-ac28-beffa264f7ac' : '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var registryPullCondition = registryUsesAbac ? '((!(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/content/read\'}) AND !(ActionMatches{\'Microsoft.ContainerRegistry/registries/repositories/metadata/read\'})) OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase \'${repositoryName}\'))' : ''

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
  scope: resourceGroup(registryResourceGroup)
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-identity'
  location: location
}

module registryPull './registry-pull.bicep' = {
  name: '${namePrefix}-registry-pull'
  scope: resourceGroup(registryResourceGroup)
  params: {
    registryName: registryName
    principalId: identity.properties.principalId
    roleDefinitionId: registryPullRoleDefinitionId
    condition: registryPullCondition
  }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

resource environment 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: '${namePrefix}-environment'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

var effectiveConfig = union(watchdogConfig, {
  authentication: 'managed_identity'
  managed_identity_client_id: identity.properties.clientId
})

resource job 'Microsoft.App/jobs@2025-07-01' = {
  name: '${namePrefix}-job'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    environmentId: environment.id
    configuration: {
      triggerType: enableSchedule ? 'Schedule' : 'Manual'
      replicaTimeout: 240
      replicaRetryLimit: 0
      scheduleTriggerConfig: enableSchedule ? {
        cronExpression: '*/5 * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      } : null
      manualTriggerConfig: enableSchedule ? null : {
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registry.properties.loginServer
          identity: identity.id
        }
      ]
      secrets: [
        {
          name: 'watchdog-config'
          value: string(effectiveConfig)
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'watchdog'
          image: containerImage
          command: [
            'python'
            '-m'
            'policyweaver.native_watchdog'
          ]
          args: [
            enableWithdrawal ? '--once' : '--inspect'
          ]
          env: [
            {
              name: 'POLICYWEAVER_CONFIG_JSON'
              secretRef: 'watchdog-config'
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
    }
  }
  dependsOn: [
    registryPull
  ]
}

output jobName string = job.name
output jobId string = job.id
output managedIdentityObjectId string = identity.properties.principalId
output managedIdentityClientId string = identity.properties.clientId
output logWorkspaceId string = logs.id
output scheduleEnabled bool = enableSchedule
output withdrawalEnabled bool = enableWithdrawal
