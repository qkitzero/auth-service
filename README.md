# Auth Service

[![release](https://img.shields.io/github/v/release/qkitzero/auth-service?logo=github)](https://github.com/qkitzero/auth-service/releases)
[![test](https://github.com/qkitzero/auth-service/actions/workflows/test.yml/badge.svg)](https://github.com/qkitzero/auth-service/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/qkitzero/auth-service/graph/badge.svg)](https://codecov.io/gh/qkitzero/auth-service)
[![Buf CI](https://github.com/qkitzero/auth-service/actions/workflows/buf-ci.yaml/badge.svg)](https://github.com/qkitzero/auth-service/actions/workflows/buf-ci.yaml)
[![OpenAPI](https://github.com/qkitzero/auth-service/actions/workflows/openapi.yml/badge.svg)](https://github.com/qkitzero/auth-service/actions/workflows/openapi.yml)

- Keycloak
- Auth0
- Microservices Architecture
- gRPC
- gRPC Gateway
- Buf ([buf.build/qkitzero-org/auth-service](https://buf.build/qkitzero-org/auth-service))
- Clean Architecture
- Docker
- Test
- Codecov
- Cloud Build
- Cloud Run

```mermaid
classDiagram
    direction LR

    class Token {
        accessToken
    	refreshToken
    }

    class User {
        id
    }
```

```mermaid
flowchart TD
    subgraph gcp[GCP]
        secret_manager[Secret Manager]

        subgraph cloud_build[Cloud Build]
            build_auth_service(Build auth-service)
            push_auth_service(Push auth-service)
            deploy_auth_service(Deploy auth-service)

            build_auth_service_gateway(Build auth-service-gateway)
            push_auth_service_gateway(Push auth-service-gateway)
            deploy_auth_service_gateway(Deploy auth-service-gateway)
        end

        subgraph artifact_registry[Artifact Registry]
            auth_service_image[(auth-service image)]
            auth_service_gateway_image[(auth-service-gateway image)]
        end

        subgraph cloud_run[Cloud Run]
            auth_service(Auth Service)
            auth_service_gateway(Auth Service Gateway)
            keycloak(Keycloak)
        end
    end

    subgraph external[External]
        auth0(Auth0)
        keycloak_db[(Keycloak DB)]
    end

    build_auth_service --> push_auth_service --> auth_service_image
    build_auth_service_gateway --> push_auth_service_gateway --> auth_service_gateway_image

    auth_service_image --> deploy_auth_service --> auth_service
    auth_service_gateway_image --> deploy_auth_service_gateway --> auth_service_gateway

    secret_manager --> deploy_auth_service
    secret_manager --> deploy_auth_service_gateway

    auth_service_gateway --> auth_service
    auth_service --> auth0

    auth_service -.-> keycloak -.-> keycloak_db
```
