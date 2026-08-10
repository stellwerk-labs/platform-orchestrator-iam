
CP_IMAGE ?= ghcr.io/stellwerk-labs/platform-orchestrator-cp:v2.0.0

compose.yaml: BUILD_ARGS := {"context":"../"}
compose.yaml: ../score.yaml Makefile compose-mixins.yaml score.provisioners.yaml score.cp.yaml
	score-compose check-version '>=0.16.0'
	score-compose init --no-sample
	cp score.provisioners.yaml .score-compose/
	cp score.cp.yaml .score-compose/
	yq -i '.containers.platform-orchestrator-cp.image = "$(CP_IMAGE)"' .score-compose/score.cp.yaml
	score-compose generate ../score.yaml --build 'platform-orchestrator-iam=$(BUILD_ARGS)'
	score-compose generate .score-compose/score.cp.yaml
	score-compose generate --publish 5432:postgres.default#platform-orchestrator-iam.postgres.host:5432 --publish 8081:platform-orchestrator-iam:8080 --publish 8082:platform-orchestrator-cp:8080
	yq eval-all '. as $$item ireduce ({}; . * $$item)' --inplace compose.yaml compose-mixins.yaml
	# Copy original iam instance as a second "self-hosted" iam instance
	yq -i '.services.platform-orchestrator-iam-self-hosted = .services.platform-orchestrator-iam-platform-orchestrator-iam' compose.yaml && \
	yq -i 'del(.services.platform-orchestrator-iam-self-hosted.build) | del(.services.platform-orchestrator-iam-self-hosted.annotations)' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.image = "integration-tests-platform-orchestrator-iam-platform-orchestrator-iam"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.hostname = "platform-orchestrator-iam-self-hosted"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.ports = [{"target": 8080, "published": "8083"}]' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.WORKOS_API_KEY = ""' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.WORKOS_CLIENT_ID = ""' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.KEYCLOAK_URL = "http://keycloak:8080"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.KEYCLOAK_REALM = "test-realm"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.KEYCLOAK_CLIENT_ID = "platform-orchestrator-iam-client"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.environment.KEYCLOAK_CLIENT_SECRET = "test-client-secret"' compose.yaml && \
	yq -i '.services.platform-orchestrator-iam-self-hosted.depends_on.keycloak.condition = "service_healthy"' compose.yaml

.PHONY: build
build: compose.yaml
	docker compose build --pull

.PHONY: test
test: compose.yaml
	mkdir -p ./mock-emails
	chmod 0777 ./mock-emails
	docker compose up --no-build -d platform-orchestrator-cp-platform-orchestrator-cp platform-orchestrator-iam-platform-orchestrator-iam platform-orchestrator-iam-self-hosted --wait
	SERVER_URL=http://$(shell score-compose resources get-outputs dns.default\#api-dns | jq -r .host):8080 \
	INTERNAL_SERVER_URL=http://localhost:8081 \
	INTERNAL_CP_URL=http://localhost:8082 \
	TEST_USER_IDENTITY_RECIPIENT=age10hmkvsqfxr5ha05ay6pqj9zdtal7pw7x2r3t4n00rzucc3en3u9q3cycqm \
	SPICEDB_URL=localhost:50051 \
	SPICEDB_TOKEN=t0k3n \
	DATABASE_URL="host=localhost port=5432 user=$(shell score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' | jq -r .username) password=$(shell score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' | jq -r .password) dbname=$(shell score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' | jq -r .name) sslmode=disable" \
	DB_CONNECTION_STRING="$(shell score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' -f 'host=localhost port=5432 dbname={{ .name }} user={{ .username }} password={{ .password }} connect_timeout=5 sslmode=disable')" \
	NATS_URL=nats://localhost:4222 \
	SELF_HOSTED_IAM_URL=http://localhost:8083 \
	go tool gotestsum --format testname ./ -test.timeout 10m -test.parallel=2 -test.v $(TESTARGS)

.PHONY: clean
clean:
	if [ -f compose.yaml ]; then docker compose down -v --remove-orphans; fi
	rm -rfv .score-compose compose.yaml mock-emails/

.PHONY: test-integration-logs
test-integration-logs:
	docker compose logs

.PHONY: connect-to-integ-db
connect-to-integ-db:
	@score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' \
		--format 'Command: docker run -it --network integration-tests_default --rm postgres:17-alpine psql -h {{ .host }} -U {{ .username }} --dbname {{ .name }}'
	@score-compose resources get-outputs 'postgres.default#platform-orchestrator-iam.postgres' --format 'Password: {{ .password }}'
