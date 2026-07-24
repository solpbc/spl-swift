# spl-swift — SPL client library for Apple platforms
#
# The five-target contract: install, test, ci, format, clean.
# ci runs BOTH destinations (macOS native + iOS Simulator) plus hygiene gates.

CI_IOS_DEST ?= platform=iOS Simulator,name=iPhone 17 Pro

.PHONY: install test test-ios ci ci-macos ci-ios hygiene format clean

install:
	@swift package resolve

test:
	@swift test --no-parallel

test-ios:
	@set -o pipefail; xcodebuild test -scheme spl-swift -destination '$(CI_IOS_DEST)' \
		-quiet 2>&1 | tail -20

ci: hygiene ci-macos ci-ios
	@echo "ci: all gates green"

ci-macos:
	@swift build -Xswiftc -warnings-as-errors
	@swift test --no-parallel

ci-ios:
	@set -o pipefail; xcodebuild test -scheme spl-swift -destination '$(CI_IOS_DEST)' \
		-quiet 2>&1 | tail -20

# Hygiene gates: forbidden constructs and internal-infrastructure strings must
# never appear in package sources. Each grep FAILS the build when it matches.
hygiene:
	@! grep -rn --include='*.swift' 'nonisolated(unsafe)' Sources/ \
		|| { echo 'hygiene: nonisolated(unsafe) is forbidden'; exit 1; }
	@! grep -rn --include='*.swift' 'DispatchQueue.main.async' Sources/ \
		|| { echo 'hygiene: DispatchQueue.main.async is forbidden'; exit 1; }
	@! grep -rn --include='*.swift' -E '(^|[^_[:alnum:]])print\(' Sources/ \
		|| { echo 'hygiene: print() is forbidden in package sources (use os.Logger via SPLLogging)'; exit 1; }
	@os_count=$$(grep -Ern --include='*.swift' '#if[[:space:]]+os\(' Sources/ | wc -l | tr -d ' '); \
		if [ "$$os_count" -gt 1 ]; then echo "hygiene: #if os(...) budget exceeded ($$os_count > 1)"; exit 1; fi
	@platform_count=$$(grep -Ern --include='*.swift' '#if[[:space:]]+!?os\(' Sources/ | wc -l | tr -d ' '); \
		if [ "$$platform_count" -gt 2 ]; then echo "hygiene: #if os/!os platform conditional budget exceeded ($$platform_count > 2)"; exit 1; fi
	@! grep -rniE 'hopper|extro|pro5e|fedora\.local|suze\.local' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: internal-infrastructure reference found'; exit 1; }
	@! grep -rniE 'spl-relay-staging\.jer-3f2\.workers\.dev' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: staging relay hostname found'; exit 1; }
	@! grep -rnE '(^|[^_[:alnum:]])(Sparkle|TestFlight|TF[0-9]+)([^_[:alnum:]]|$$)' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: app-distribution narrative found'; exit 1; }
	@! grep -rnE '(^|[^._[:alnum:]-])([[:alnum:]._/-]+\.entitlements|com\.apple\.[[:alnum:]._/-]+)([^._[:alnum:]-]|$$)' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: Apple code-signing entitlement reference found'; exit 1; }
	@! grep -rnE '[Ff]ounder[- ]decided[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: founder-decision datestamp found'; exit 1; }
	@! grep -rniE '^[[:space:]]*//.*(^|[^_[:alnum:]])(lode|lodes|arc|arcs|request[-_ ]?id)([^_[:alnum:]]|$$)' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: internal lode/arc/request-id comment found'; exit 1; }
	@! grep -rnE "(^|[^_[:alnum:]])(Jer['’]s|Jeremy|Jared)([^_[:alnum:]]|$$)" Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: person-name literal found'; exit 1; }
	@! grep -rniE '(^|[^_[:alnum:]])solstone-macos-internal([^_[:alnum:]]|$$)' Sources/ Tests/ README.md AGENTS.md \
		|| { echo 'hygiene: internal macOS repo reference found'; exit 1; }
	@missing=$$(find Sources -name '*.swift' -exec grep -L 'SPDX-License-Identifier: AGPL-3.0-only' {} +); \
		if [ -n "$$missing" ]; then echo "hygiene: missing SPDX header: $$missing"; exit 1; fi
	@test ! -d .github/workflows \
		|| { echo 'hygiene: CI workflows are not used in this repo'; exit 1; }
	@echo "hygiene: clean"

format:
	@swift format --recursive --in-place Sources Tests 2>/dev/null \
		|| echo "format: swift format unavailable; skipped"

clean:
	@rm -rf .build DerivedData
