targetScope = 'resourceGroup'

param registryName string
param principalId string
param roleDefinitionId string
param condition string = ''

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
}

resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, principalId, roleDefinitionId)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
    principalId: principalId
    principalType: 'ServicePrincipal'
    condition: empty(condition) ? null : condition
    conditionVersion: empty(condition) ? null : '2.0'
  }
}
