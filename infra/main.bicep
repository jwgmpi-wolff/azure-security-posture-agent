targetScope = 'resourceGroup'

@description('Deployment location for all regional resources.')
param location string = resourceGroup().location

@description('Tenant ID for delegated token validation.')
param tenantId string

@description('Entra client ID for browser and Copilot OAuth flows.')
param clientId string

@description('OAuth authority URL for the deployed app.')
param authority string

@description('Name of the Azure Container Registry.')
param registryName string

@description('Container app name.')
param containerAppName string = 'azure-security-posture-agent'

@description('Container Apps environment name.')
param managedEnvironmentName string = 'sec-posture-env'

@description('Log Analytics workspace name.')
param logAnalyticsWorkspaceName string = 'sec-posture-law'

@description('Application Insights component name.')
param applicationInsightsName string = 'appi-sec-posture'

@description('Whether to enable a system-assigned managed identity on the container app.')
param enableManagedIdentity bool = true

@description('Allowed browser origin list.')
param allowedOrigins array = [
  'http://localhost:8000'
]

var containerImage = 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    DisableLocalAuth: true
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: managedEnvironmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  identity: enableManagedIdentity ? {
    type: 'SystemAssigned'
  } : null
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      ingress: {
        external: true
        targetPort: 80
        transport: 'auto'
      }
      secrets: [
        {
          name: 'appinsights-connection'
          value: applicationInsights.properties.ConnectionString
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: containerImage
          resources: {
            cpu: json('0.75')
            memory: '1.5Gi'
          }
          env: [
            {
              name: 'SECPA_ENTRA_CLIENT_ID'
              value: clientId
            }
            {
              name: 'SECPA_ENTRA_AUTHORITY'
              value: authority
            }
            {
              name: 'SECPA_COPILOT_AUDIENCE'
              value: 'api://${clientId}'
            }
            {
              name: 'SECPA_ALLOWED_ORIGINS'
              value: string(allowedOrigins)
            }
            {
              name: 'SECPA_SESSION_COOKIE_SECURE'
              value: 'true'
            }
            {
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
              secretRef: 'appinsights-connection'
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
}

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableManagedIdentity) {
  name: guid(registry.id, containerAppName, 'acrpull')
  scope: registry
  properties: {
    principalId: app.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalType: 'ServicePrincipal'
  }
}

output containerAppUrl string = app.properties.configuration.ingress.fqdn
output registryLoginServer string = registry.properties.loginServer
output tenantBoundTo string = tenantId
