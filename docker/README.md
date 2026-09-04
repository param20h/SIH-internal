# docker/

Shared infrastructure configuration that doesn't belong to a single service
(database init scripts, reverse-proxy config, etc.) lives here as the project
grows. Service-specific Dockerfiles live next to their service instead:
`backend/Dockerfile` and `frontend/Dockerfile`. Orchestration is defined in
the root `docker-compose.yml`.
