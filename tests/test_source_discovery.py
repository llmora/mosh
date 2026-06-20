from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.config import AppConfig
from mosh.crews.discovery_source.agents import build_discovery_source_agents
from mosh.crews.discovery_source.crew import (
    CrewAIDiscoverySourceCrewRunner,
    CrewAIUnavailable,
    DiscoverySourceCrewState,
    DiscoverySourceOrchestrator,
    _apply_route_resolutions,
    _build_yaml_discovery_source_crew,
    _route_id,
)
from mosh.crews.discovery_source.tools import (
    ConfigInventoryTool,
    DependencyInventoryTool,
    MAX_INDEXED_FILES,
    RouteApiExtractorTool,
    SourceInventoryTool,
    build_source_index,
)
from mosh.memory import FileMemory
from tests.fakes import FakeRuntimeCrewAI, FakeDiscoverySourceRunner
from tests.fixtures import fixture_source_tree


class DiscoverySourceToolTests(unittest.TestCase):
    def test_source_inventory_indexes_security_relevant_files_and_ignores_vendor_dirs(self) -> None:
        with fixture_source_tree() as source:
            inventory = SourceInventoryTool().run(str(source))

        paths = {file["path"] for file in inventory["files"]}
        self.assertIn("app.py", paths)
        self.assertIn("package.json", paths)
        self.assertIn("package-lock.json", paths)
        self.assertIn("pyproject.toml", paths)
        self.assertIn("Dockerfile", paths)
        self.assertIn(".env.example", paths)
        self.assertIn("apps/api/package.json", paths)
        self.assertIn("services/classifier/requirements.txt", paths)
        self.assertIn("apps/android/src/main/AndroidManifest.xml", paths)
        self.assertIn("apps/ios/Info.plist", paths)
        self.assertIn("apps/ios/Podfile.lock", paths)
        self.assertIn("apps/ios/Pods/Manifest.lock", paths)
        self.assertIn("apps/ios/Pods/Stripe/Stripe/StripeiOS/Source/STPAddPaymentPassViewController.swift", paths)
        self.assertNotIn(".github/.DS_Store", paths)
        self.assertNotIn("node_modules/ignored/index.js", paths)
        self.assertNotIn(".gradle/caches/generated.py", paths)
        self.assertNotIn(".derivedData/Build/generated.py", paths)
        self.assertNotIn("build-maestro/generated/generated.py", paths)
        self.assertNotIn("build-share-flow/generated/generated.py", paths)
        self.assertEqual(inventory["languages"]["python"], 2)
        self.assertTrue(any(file["role"] == "lockfile" for file in inventory["files"]))
        self.assertIn("node_modules", inventory["ignored_dirs"])
        self.assertIn(".gradle", inventory["ignored_dirs"])
        self.assertIn(".derivedData", inventory["ignored_dirs"])
        self.assertIn("build-maestro", inventory["ignored_dirs"])
        self.assertIn("build-share-flow", inventory["ignored_dirs"])
        self.assertEqual(MAX_INDEXED_FILES, 10000)
        apps = {app["app_id"]: app for app in inventory["apps"]}
        self.assertIn("root", apps)
        self.assertIn("apps-api", apps)
        self.assertIn("apps-android", apps)
        self.assertIn("apps-ios", apps)
        self.assertIn("apps-ios-share", apps)
        self.assertIn("services-classifier", apps)
        self.assertEqual(apps["apps-android"]["type"], "android-app")
        self.assertEqual(apps["apps-ios"]["type"], "ios-app")
        self.assertEqual(apps["services-classifier"]["type"], "web-api")
        self.assertIn("fastapi", apps["services-classifier"]["frameworks"])
        entrypoint_paths = {entrypoint["path"] for entrypoint in inventory["entrypoints"]}
        self.assertIn("apps/api/src/server.ts", entrypoint_paths)
        self.assertIn("apps/android/src/main/java/com/example/MainActivity.kt", entrypoint_paths)
        self.assertIn("apps/ios/AppDelegate.swift", entrypoint_paths)
        self.assertIn("apps/ios-share/ShareViewController.swift", entrypoint_paths)
        self.assertIn("services/classifier/main.py", entrypoint_paths)
        for app in inventory["apps"]:
            self.assertNotIn("Pods", Path(app["root"]).parts)
            self.assertFalse(any("Pods" in Path(manifest).parts for manifest in app.get("manifests", [])))
            self.assertFalse(any("Pods" in Path(entrypoint["path"]).parts for entrypoint in app.get("entrypoints", [])))
        self.assertFalse(any("Pods" in Path(entrypoint_path).parts for entrypoint_path in entrypoint_paths))

    def test_route_extractor_finds_framework_routes_without_vendor_routes(self) -> None:
        with fixture_source_tree() as source:
            routes = RouteApiExtractorTool().run(str(source))

        route_values = {route["route"] for route in routes["routes"]}
        self.assertIn("/api/users/<user_id>", route_values)
        self.assertIn("/api/users", route_values)
        self.assertIn("/classify", route_values)
        self.assertNotIn("/ignored", route_values)
        self.assertNotIn("/gradle-cache", route_values)
        self.assertNotIn("/derived-data", route_values)
        self.assertNotIn("/build-maestro", route_values)
        self.assertNotIn("/build-share-flow", route_values)
        full_routes = {route["full_route"] for route in routes["routes"]}
        self.assertIn("/api/v1/users", full_routes)
        self.assertIn("/check-sms", full_routes)
        self.assertIn("/v1/check-sms", full_routes)
        self.assertIn("/api/v1/check-sms", full_routes)
        mounted_route = next(route for route in routes["routes"] if route["full_route"] == "/api/v1/users")
        self.assertEqual(mounted_route["route"], "/users")
        self.assertEqual(mounted_route["mount_prefix"], "/api/v1")
        self.assertEqual(mounted_route["app_id"], "apps-api")
        self.assertEqual(mounted_route["scope"], "production")
        test_route = next(route for route in routes["routes"] if route["route"] == "/test-only")
        self.assertEqual(test_route["scope"], "test")
        admin_route = next(route for route in routes["routes"] if route["route"] == "/admin")
        self.assertIn("requireAuth", admin_route["middleware"])
        wrapper_route = next(route for route in routes["routes"] if route["full_route"] == "/api/v1/check-sms")
        self.assertEqual(wrapper_route["registration"], "custom-wrapper")
        get_route = next(route for route in routes["routes"] if route["route"] == "/api/users/<user_id>")
        self.assertEqual(get_route["method"], "GET")
        self.assertEqual(get_route["path"], "app.py")
        self.assertEqual(get_route["handler"], "get_user")

    def test_route_extractor_finds_rails_routes_and_updates_source_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            routes_file = source / "api" / "config" / "routes.rb"
            routes_file.parent.mkdir(parents=True)
            routes_file.write_text(
                "\n".join(
                    [
                        "Rails.application.routes.draw do",
                        "  get 'billing/get'",
                        "  get 'configuration/get'",
                        "  scope '/api' do",
                        "    get '/ping' => 'ping#ping'",
                        "    post '/billing/webhook', to: 'billing#stripe_webhook'",
                        "    get '/bookings/:id' => 'bookings#read'",
                        "    constraints(->(_request) { Rails.configuration.x.drive.expose_internal_api }) do",
                        "      scope '/backoffice' do",
                        "        scope '/users' do",
                        "          get '/content' => 'backoffice#users_content'",
                        "        end",
                        "      end",
                        "    end",
                        "    namespace :driver do",
                        "      get '/schedules' => 'schedules#list'",
                        "    end",
                        "  end",
                        "end",
                    ]
                ),
                encoding="utf-8",
            )

            routes = RouteApiExtractorTool().run(str(source))

        routes_by_full_path = {route["full_route"]: route for route in routes["routes"]}
        self.assertIn("/billing/get", routes_by_full_path)
        self.assertIn("/configuration/get", routes_by_full_path)
        self.assertIn("/api/ping", routes_by_full_path)
        self.assertIn("/api/billing/webhook", routes_by_full_path)
        self.assertIn("/api/bookings/:id", routes_by_full_path)
        self.assertIn("/api/backoffice/users/content", routes_by_full_path)
        self.assertIn("/api/driver/schedules", routes_by_full_path)
        self.assertEqual(routes_by_full_path["/api/ping"]["framework"], "rails")
        self.assertEqual(routes_by_full_path["/api/ping"]["handler"], "ping#ping")
        self.assertEqual(routes_by_full_path["/billing/get"]["handler"], "billing#get")
        self.assertEqual(routes_by_full_path["/api/billing/webhook"]["method"], "POST")
        self.assertEqual(routes_by_full_path["/api/driver/schedules"]["handler"], "driver/schedules#list")
        self.assertTrue(routes_by_full_path["/api/backoffice/users/content"]["conditional"])

        source_index = build_source_index(
            {"schema": "mosh.source-info.v1", "path": str(source)},
            {"files": [], "apps": [], "languages": {}},
            routes,
            {"dependencies": []},
            {"configuration": []},
        )
        self.assertEqual(source_index["summary"]["routes_identified"], len(routes["routes"]))
        self.assertEqual(source_index["inventory"]["apis"], routes["routes"])
        self.assertTrue(source_index["evidence_refs"])

    def test_dependency_and_config_inventory_extract_supported_evidence(self) -> None:
        with fixture_source_tree() as source:
            dependencies = DependencyInventoryTool().run(str(source))
            configuration = ConfigInventoryTool().run(str(source))

        dependency_names = {dependency["name"] for dependency in dependencies["dependencies"]}
        dependency_manifests = {manifest["path"] for manifest in dependencies["manifests"]}
        config_paths = {item["path"] for item in configuration["configuration"]}
        self.assertIn("express", dependency_names)
        self.assertIn("fastapi", dependency_names)
        self.assertIn("flask", dependency_names)
        self.assertIn("sqlalchemy", dependency_names)
        self.assertIn("androidx.core:core-ktx", dependency_names)
        self.assertIn("Alamofire", dependency_names)
        cocoapods_dependencies = {
            (dependency["name"], dependency["version"], dependency["manifest"])
            for dependency in dependencies["dependencies"]
            if dependency["ecosystem"] == "cocoapods"
        }
        self.assertIn(("Alamofire", "~> 5.9", "apps/ios/Podfile"), cocoapods_dependencies)
        self.assertIn(("Alamofire", "5.9.1", "apps/ios/Podfile.lock"), cocoapods_dependencies)
        self.assertIn(("Stripe/Core", "24.0.0", "apps/ios/Podfile.lock"), cocoapods_dependencies)
        self.assertNotIn(("Stripe/Core", "24.0.0", "apps/ios/Pods/Manifest.lock"), cocoapods_dependencies)
        self.assertIn("apps/ios/Pods/Manifest.lock", dependency_manifests)
        self.assertIn("Dockerfile", config_paths)
        self.assertIn(".env.example", config_paths)
        self.assertNotIn(".github/.DS_Store", config_paths)
        env_names = {item["name"] for item in configuration["environment_variables"]}
        self.assertIn("JWT_SECRET", env_names)
        self.assertIn("MODEL_PATH", env_names)
        compose_services = {
            service["name"]
            for item in configuration["compose_topology"]
            for service in item["services"]
        }
        self.assertIn("api", compose_services)
        self.assertIn("classifier", compose_services)

    def test_dependency_inventory_reads_cocoapods_manifest_lock_without_podfile_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            pods = source / "Pods"
            pods.mkdir()
            (pods / "Manifest.lock").write_text(
                "\n".join(
                    [
                        "PODS:",
                        "  - Stripe/Core (24.0.0):",
                        "    - Stripe/Payments (= 24.0.0)",
                        "",
                        "DEPENDENCIES:",
                        "  - Stripe/Core",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            dependencies = DependencyInventoryTool().run(str(source))

        cocoapods_dependencies = {
            (dependency["name"], dependency["version"], dependency["manifest"])
            for dependency in dependencies["dependencies"]
            if dependency["ecosystem"] == "cocoapods"
        }
        self.assertIn(("Stripe/Core", "24.0.0", "Pods/Manifest.lock"), cocoapods_dependencies)

    def test_route_resolution_only_updates_existing_route_ids(self) -> None:
        routes = {
            "schema": "mosh.source-routes.v1",
            "routes": [
                {
                    "method": "GET",
                    "path": "app/routes.py",
                    "line": 12,
                    "route": "/users",
                    "full_route": "/users",
                    "handler": "list_users",
                }
            ],
        }
        route = routes["routes"][0]
        route_resolution = {
            "resolved_routes": [
                {
                    "route_id": _route_id(route),
                    "full_route": "api/v1/users",
                    "mount_prefix": "/api/v1",
                    "confidence": "high",
                    "reason": "Router is mounted under /api/v1.",
                    "evidence": ["app/main.py:8"],
                },
                {
                    "route_id": "missing|route",
                    "full_route": "/invented",
                },
            ]
        }

        updated, applied = _apply_route_resolutions(routes, route_resolution)

        self.assertEqual(applied, 1)
        self.assertEqual(len(updated["routes"]), 1)
        self.assertEqual(updated["routes"][0]["full_route"], "/api/v1/users")
        self.assertEqual(updated["routes"][0]["deterministic_full_route"], "/users")
        self.assertEqual(updated["routes"][0]["route_resolution_source"], "model-assisted")
        self.assertEqual(updated["routes"][0]["route_resolution_evidence"], ["app/main.py:8"])


class DiscoverySourceCrewTests(unittest.TestCase):
    def test_discovery_source_crewai_crew_attaches_usage_event_listener(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(openrouter_api_key="test-key")
            agents = build_discovery_source_agents(config)
            state = DiscoverySourceCrewState(
                source="/tmp/source",
                report_dir=Path(directory),
                memory=FileMemory(Path(directory)),
            )
            crew_def = _build_yaml_discovery_source_crew(
                crewai=FakeRuntimeCrewAI,
                config=config,
                state=state,
                intake_agent=agents.intake,
                mapper_agent=agents.mapper,
                dependency_config_agent=agents.dependency_config,
                reporter_agent=agents.reporter,
            )

            crew = crew_def.crew()

            self.assertEqual(len(crew.event_listeners), 1)

    def test_crewai_runner_requires_llm_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = CrewAIDiscoverySourceCrewRunner(AppConfig(openrouter_api_key=None))
            memory = FileMemory(Path(directory))

            with self.assertRaisesRegex(CrewAIUnavailable, "OPENROUTER_API_KEY"):
                runner.run("/tmp/source", Path(directory), memory)

    def test_discovery_source_orchestrator_writes_report_memory_and_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with fixture_source_tree() as source:
                output_root = Path(directory) / "report"
                orchestrator = DiscoverySourceOrchestrator(
                    AppConfig(openrouter_api_key="test-key"),
                    output_root=output_root,
                    crew_runner=FakeDiscoverySourceRunner(),
                )

                expected_dir = output_root / "eng_test" / "assets" / "asset_source_1" / "discovery"
                report_dir = orchestrator.run(str(source), report_dir=expected_dir)

                self.assertEqual(report_dir, expected_dir)
                self.assertTrue((report_dir / "report.md").exists())
                self.assertTrue((report_dir / "memory.json").exists())
                self.assertTrue((report_dir / "events.json").exists())
                self.assertFalse((report_dir / "report.json").exists())

                memory = json.loads((report_dir / "memory.json").read_text(encoding="utf-8"))
                self.assertTrue(any(item["kind"] == "source_index" for item in memory))
                self.assertTrue(any(item["kind"] == "source_route_resolution" for item in memory))
                self.assertTrue(any(item["kind"] == "source_component_map" for item in memory))
                self.assertTrue(any(item["kind"] == "source_gap_analysis" for item in memory))
                source_index = next(item["content"] for item in memory if item["kind"] == "source_index")
                self.assertEqual(source_index["schema"], "mosh.source-index.v1")
                self.assertEqual(source_index["route_resolution"]["schema"], "mosh.source-route-resolution.v1")
                self.assertEqual(source_index["component_map"]["schema"], "mosh.source-component-map.v1")
                self.assertEqual(source_index["gap_analysis"]["schema"], "mosh.source-gap-analysis.v1")
                self.assertTrue(source_index["inventory"]["routes"])
                self.assertTrue(source_index["inventory"]["dependencies"])
                self.assertTrue(source_index["inventory"]["environment_variables"])
                self.assertTrue(source_index["inventory"]["compose_topology"])
                app_ids = {app["app_id"] for app in source_index["inventory"]["apps"]}
                self.assertIn("apps-android", app_ids)
                self.assertIn("apps-ios", app_ids)
                self.assertIn("services-classifier", app_ids)
                self.assertIn("/api/v1/users", {route["full_route"] for route in source_index["inventory"]["routes"]})

                markdown = (report_dir / "report.md").read_text(encoding="utf-8")
                self.assertIn("# Source Discovery Report", markdown)
                self.assertIn("Application Units", markdown)
                self.assertIn("Application Purpose", markdown)
                self.assertIn("Business Components", markdown)
                self.assertIn("Sensitive Data And Trust Boundaries", markdown)
                self.assertIn("Discovery Gaps", markdown)
                self.assertIn("android-app", markdown)
                self.assertIn("ios-app", markdown)
                self.assertIn("Routes And API Candidates", markdown)
                self.assertIn("Environment Variable Inventory", markdown)
                self.assertIn("Docker Compose Topology", markdown)
                self.assertIn("model-assisted", markdown)
                self.assertIn("/api/v1/users", markdown)


if __name__ == "__main__":
    unittest.main()
