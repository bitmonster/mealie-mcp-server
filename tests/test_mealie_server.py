from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SERVER_PATH = Path(__file__).resolve().parents[1] / "mealie_server.py"


def load_server():
    spec = importlib.util.spec_from_file_location("mealie_server_under_test", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class MealieMcpRegressionTests(unittest.TestCase):
    def setUp(self):
        self.server = load_server()

    def test_url_import_normalizes_raw_slug_to_dictionary(self):
        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "ALLOW_URL_IMPORTS", True),
            patch.object(
                self.server,
                "_validate_remote_source_url",
                return_value="https://example.invalid/recipe",
            ),
            patch.object(
                self.server,
                "_json_request",
                return_value="thailandischer-glasnudelsalat-yum-woon-sen",
            ),
        ):
            result = self.server.mealie_create_recipe_from_url(
                "https://example.invalid/recipe",
                confirmed_by_user=True,
            )

        self.assertEqual(
            result,
            {
                "success": True,
                "slug": "thailandischer-glasnudelsalat-yum-woon-sen",
                "url": (
                    f"{self.server.PUBLIC_URL}/g/home/r/"
                    "thailandischer-glasnudelsalat-yum-woon-sen"
                ),
            },
        )

    def test_recipe_import_scope_allows_ingredient_parser(self):
        with patch.object(self.server, "MUTATION_SCOPE", "recipe_import"):
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST", "/api/parser/ingredients"
                )
            )
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST", "/api/parser/ingredient"
                )
            )

    def test_parse_ingredients_sends_v320_string_list(self):
        captured_body = None

        def fake_request(method, path, *, body=None, **kwargs):
            nonlocal captured_body
            self.assertEqual((method, path), ("POST", "/api/parser/ingredients"))
            captured_body = body
            return {"ingredients": []}

        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", side_effect=fake_request),
        ):
            self.server.mealie_parse_ingredients(["250 g Karotten"])

        self.assertEqual(captured_body, {"ingredients": ["250 g Karotten"]})

    def test_update_recipe_image_requires_explicit_confirmation(self):
        with (
            patch.object(self.server, "_json_request") as json_request,
            patch.object(self.server, "_multipart_request") as multipart_request,
        ):
            with self.assertRaisesRegex(RuntimeError, "explizite Bestätigung"):
                self.server.mealie_update_recipe_image(
                    "ddr-tomatensosse",
                    "https://example.invalid/tomatensosse.jpg",
                    confirmed_by_user=False,
                )

        json_request.assert_not_called()
        multipart_request.assert_not_called()

    def test_update_recipe_image_uploads_real_multipart_file(self):
        image_bytes = b"real-jpeg-image-bytes"
        multipart_calls = []
        get_calls = []

        def fake_json_request(method, path, **kwargs):
            self.assertEqual(method, "GET")
            get_calls.append(path)
            return {
                "id": "recipe-id",
                "slug": "ddr-tomatensosse",
                "image": "tomatensosse.webp" if len(get_calls) > 1 else None,
            }

        def fake_multipart_request(method, path, *, fields=None, files=None, **kwargs):
            multipart_calls.append((method, path, fields, files))
            return {"image": "tomatensosse.webp"}

        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", side_effect=fake_json_request),
            patch.object(
                self.server,
                "_read_binary_source",
                return_value=("ddr-tomatensosse.jpg", image_bytes, "image/jpeg"),
            ),
            patch.object(self.server, "_multipart_request", side_effect=fake_multipart_request),
        ):
            result = self.server.mealie_update_recipe_image(
                "recipe-id",
                "https://example.invalid/ddr-tomatensosse.jpg",
                confirmed_by_user=True,
            )

        self.assertEqual(
            multipart_calls,
            [
                (
                    "PUT",
                    "/api/recipes/ddr-tomatensosse/image",
                    {"extension": "jpg"},
                    {"image": ("ddr-tomatensosse.jpg", image_bytes, "image/jpeg")},
                )
            ],
        )
        self.assertEqual(
            get_calls,
            ["/api/recipes/recipe-id", "/api/recipes/ddr-tomatensosse"],
        )
        self.assertEqual(result["slug"], "ddr-tomatensosse")
        self.assertEqual(result["image"], "tomatensosse.webp")
        self.assertTrue(result["image_uploaded"])
        self.assertFalse(result["crop_applied"])

    def test_household_mutation_scopes_match_v320_openapi_methods(self):
        with patch.object(self.server, "MUTATION_SCOPE", "shopping"):
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "PUT", "/api/households/shopping/items/item-id"
                )
            )
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST",
                    "/api/households/shopping/lists/list-id/recipe/recipe-id",
                )
            )
        with patch.object(self.server, "MUTATION_SCOPE", "mealplan"):
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "PUT", "/api/households/mealplans/42"
                )
            )
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST", "/api/households/mealplans/random"
                )
            )
        with patch.object(self.server, "MUTATION_SCOPE", "recipe_import"):
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "DELETE", "/api/recipes/test/image"
                )
            )
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST", "/api/recipes/test/duplicate"
                )
            )
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "PATCH", "/api/recipes/test/last-made"
                )
            )

    def test_api_operations_excludes_sensitive_endpoints_by_default(self):
        spec = {
            "info": {"version": "v3.20.1"},
            "paths": {
                "/api/households/mealplans/{item_id}": {
                    "get": {
                        "operationId": "get_mealplan",
                        "summary": "Get mealplan",
                        "tags": ["Households: Mealplans"],
                        "responses": {"200": {"content": {"application/json": {}}}},
                    }
                },
                "/api/admin/backups": {
                    "get": {
                        "operationId": "get_backups",
                        "summary": "Get backups",
                        "tags": ["Admin: Backups"],
                        "responses": {"200": {"content": {"application/json": {}}}},
                    }
                },
            },
        }
        with patch.object(self.server, "_get_openapi_spec", return_value=spec):
            result = self.server.mealie_api_operations()
            sensitive = self.server.mealie_api_operations(include_sensitive=True)

        self.assertEqual(result["total_matching"], 1)
        self.assertEqual(result["operations"][0]["operation_id"], "get_mealplan")
        self.assertEqual(sensitive["total_matching"], 2)
        admin = next(
            item for item in sensitive["operations"] if item["operation_id"] == "get_backups"
        )
        self.assertTrue(admin["sensitive"])

    def test_api_operation_request_resolves_path_and_requires_confirmation(self):
        spec = {
            "paths": {
                "/api/households/mealplans/{item_id}": {
                    "put": {
                        "operationId": "update_mealplan",
                        "tags": ["Households: Mealplans"],
                        "requestBody": {
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                        "responses": {"200": {"content": {"application/json": {}}}},
                    }
                }
            }
        }
        with patch.object(self.server, "_get_openapi_spec", return_value=spec):
            with self.assertRaisesRegex(RuntimeError, "explizite Bestätigung"):
                self.server.mealie_api_operation_request(
                    "update_mealplan",
                    path_params={"item_id": 42},
                    body={"title": "Abendessen"},
                )

        with (
            patch.object(self.server, "_get_openapi_spec", return_value=spec),
            patch.object(self.server, "_require_mutations") as require_mutations,
            patch.object(self.server, "_json_request", return_value={"id": 42}) as request,
        ):
            result = self.server.mealie_api_operation_request(
                "update_mealplan",
                path_params={"item_id": 42},
                body={"title": "Abendessen"},
                confirmed_by_user=True,
            )

        require_mutations.assert_called_once_with(
            "/api/households/mealplans/42", "PUT"
        )
        request.assert_called_once_with(
            "PUT",
            "/api/households/mealplans/42",
            params=None,
            body={"title": "Abendessen"},
        )
        self.assertEqual(result, {"id": 42})

    def test_openapi_operation_validates_required_query_and_body_fields(self):
        spec = {
            "paths": {
                "/api/example": {
                    "parameters": [
                        {"name": "household", "in": "query", "required": True}
                    ],
                    "post": {
                        "operationId": "create_example",
                        "tags": ["Recipe: CRUD"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name"],
                                    }
                                }
                            },
                        },
                        "responses": {"200": {"content": {"application/json": {}}}},
                    },
                }
            }
        }
        with (
            patch.object(self.server, "_get_openapi_spec", return_value=spec),
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request") as request,
        ):
            with self.assertRaisesRegex(RuntimeError, "Queryparameter.*household"):
                self.server.mealie_api_operation_request(
                    "create_example",
                    body={"name": "Test"},
                    confirmed_by_user=True,
                )
            with self.assertRaisesRegex(RuntimeError, "Body-Felder.*name"):
                self.server.mealie_api_operation_request(
                    "create_example",
                    query_params={"household": "home"},
                    body={},
                    confirmed_by_user=True,
                )
        request.assert_not_called()

    def test_status_returns_minimal_auth_state_without_user_pii(self):
        with patch.object(
            self.server,
            "_json_request",
            side_effect=[
                {"version": "v3.20.1"},
                {"id": "u1", "username": "private", "email": "private@example", "admin": True},
            ],
        ):
            result = self.server.mealie_status()
        self.assertEqual(result["authentication"], {"authenticated": True, "admin": True})
        self.assertNotIn("user", result)
        self.assertNotIn("private", str(result))

    def test_api_operation_request_blocks_sensitive_operation_even_if_confirmed(self):
        spec = {
            "paths": {
                "/api/admin/backups": {
                    "post": {
                        "operationId": "create_backup",
                        "tags": ["Admin: Backups"],
                        "requestBody": {
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                    }
                }
            }
        }
        with patch.object(self.server, "_get_openapi_spec", return_value=spec):
            with self.assertRaisesRegex(RuntimeError, "sensiblen"):
                self.server.mealie_api_operation_request(
                    "create_backup", confirmed_by_user=True
                )

    def test_raw_api_paths_cannot_bypass_sensitive_guard(self):
        bypasses = [
            "/api/%61dmin/backups",
            "/api/%2561dmin/backups",
            "/api/users%2Fself",
            "/api/recipes/../admin/backups",
            "/api\\admin\\backups",
        ]
        with patch.object(self.server, "_json_request") as request:
            for path in bypasses:
                with self.subTest(path=path):
                    with self.assertRaisesRegex(RuntimeError, "Sensible"):
                        self.server.mealie_api_get(path)
        request.assert_not_called()

    def test_update_shopping_item_fetches_merges_and_puts_full_model(self):
        current = {
            "id": "item-id",
            "shoppingListId": "list-id",
            "display": "Milch",
            "quantity": 1,
            "checked": False,
            "position": 0,
        }
        calls = []

        def fake_request(method, path, *, body=None, **kwargs):
            calls.append((method, path, body))
            if method == "GET":
                return current
            return {**current, **(body or {})}

        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", side_effect=fake_request),
        ):
            result = self.server.mealie_update_shopping_item(
                "item-id", {"checked": True}, confirmed_by_user=True
            )

        self.assertEqual(calls[0], ("GET", "/api/households/shopping/items/item-id", None))
        self.assertEqual(calls[1][0:2], ("PUT", "/api/households/shopping/items/item-id"))
        self.assertEqual(calls[1][2]["shoppingListId"], "list-id")
        self.assertTrue(calls[1][2]["checked"])
        self.assertTrue(result["checked"])

    def test_add_recipe_to_shopping_list_uses_v320_endpoint(self):
        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", return_value={"created": 4}) as request,
        ):
            result = self.server.mealie_add_recipe_to_shopping_list(
                "list-id", "recipe-id", 2, confirmed_by_user=True
            )

        request.assert_called_once_with(
            "POST",
            "/api/households/shopping/lists/list-id/recipe/recipe-id",
            body={"recipeIncrementQuantity": 2},
        )
        self.assertEqual(result, {"created": 4})

    def test_create_mealplan_uses_v320_schema(self):
        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", return_value={"id": 42}) as request,
        ):
            result = self.server.mealie_create_mealplan(
                "2026-07-15",
                entry_type="dinner",
                title="Tomatensoße",
                recipe_id="recipe-id",
                confirmed_by_user=True,
            )

        request.assert_called_once_with(
            "POST",
            "/api/households/mealplans",
            body={
                "date": "2026-07-15",
                "entryType": "dinner",
                "title": "Tomatensoße",
                "text": "",
                "recipeId": "recipe-id",
            },
        )
        self.assertEqual(result, {"id": 42})

    def test_upload_recipe_asset_uses_real_multipart(self):
        content = b"source-image"
        with (
            patch.object(self.server, "_json_request", return_value={"slug": "test"}),
            patch.object(self.server, "_require_mutations"),
            patch.object(
                self.server,
                "_read_binary_source",
                return_value=("quelle.jpg", content, "image/jpeg"),
            ),
            patch.object(self.server, "_multipart_request", return_value={"name": "Quelle"}) as upload,
        ):
            result = self.server.mealie_upload_recipe_asset(
                "test",
                "https://example.invalid/quelle.jpg",
                asset_name="Quelle",
                confirmed_by_user=True,
            )

        upload.assert_called_once_with(
            "POST",
            "/api/recipes/test/assets",
            fields={"name": "Quelle", "icon": ""},
            files={"file": ("quelle.jpg", content, "image/jpeg")},
        )
        self.assertEqual(result["slug"], "test")
        self.assertTrue(result["asset_uploaded"])

    def test_multipart_operation_request_resolves_files_and_scope(self):
        spec = {
            "paths": {
                "/api/recipes/create/zip": {
                    "post": {
                        "operationId": "create_recipe_zip",
                        "tags": ["Recipe: CRUD"],
                        "parameters": [
                            {"name": "replace", "in": "query", "required": True}
                        ],
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {"schema": {"type": "object"}}
                            }
                        },
                    }
                }
            }
        }
        content = b"zip-bytes"
        with (
            patch.object(self.server, "_get_openapi_spec", return_value=spec),
            patch.object(self.server, "_require_mutations") as require_mutations,
            patch.object(
                self.server,
                "_read_binary_source",
                return_value=("recipes.zip", content, "application/zip"),
            ),
            patch.object(self.server, "_multipart_request", return_value={"queued": True}) as upload,
        ):
            result = self.server.mealie_api_multipart_operation_request(
                "create_recipe_zip",
                query_params={"replace": True},
                fields={"includeTags": True},
                file_sources={"archive": "https://example.invalid/recipes.zip"},
                confirmed_by_user=True,
            )

        require_mutations.assert_called_once_with("/api/recipes/create/zip", "POST")
        upload.assert_called_once_with(
            "POST",
            "/api/recipes/create/zip",
            params={"replace": True},
            fields={"includeTags": True},
            files={"archive": ("recipes.zip", content, "application/zip")},
        )
        self.assertEqual(result, {"queued": True})

    def test_download_operation_writes_binary_to_controlled_directory(self):
        spec = {
            "paths": {
                "/api/recipes/{slug}/exports": {
                    "get": {
                        "operationId": "export_recipe",
                        "tags": ["Recipe: Exports"],
                        "responses": {
                            "200": {"content": {"application/octet-stream": {}}}
                        },
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch.object(self.server, "_get_openapi_spec", return_value=spec),
                patch.object(self.server, "DOWNLOAD_DIR", Path(tmpdir)),
                patch.object(
                    self.server,
                    "_download_api_binary",
                    return_value=("recipe.zip", b"zip-data", "application/zip"),
                ),
            ):
                result = self.server.mealie_api_download(
                    "export_recipe", path_params={"slug": "test"}
                )

            saved = Path(result["path"])
            self.assertTrue(saved.exists())
            self.assertEqual(saved.read_bytes(), b"zip-data")
            self.assertEqual(result["content_type"], "application/zip")

    def test_mutation_scope_is_fail_closed_unless_all_is_explicit(self):
        for scope in ("", "none", "unknown-scope"):
            with self.subTest(scope=scope), patch.object(
                self.server, "MUTATION_SCOPE", scope
            ):
                self.assertFalse(
                    self.server._mutation_allowed_by_scope(
                        "POST", "/api/recipes/arbitrary/action"
                    )
                )
        with patch.object(self.server, "MUTATION_SCOPE", "all"):
            self.assertTrue(
                self.server._mutation_allowed_by_scope(
                    "POST", "/api/recipes/arbitrary/action"
                )
            )

    def test_binary_source_is_confined_to_allowed_local_roots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            allowed = base / "allowed"
            allowed.mkdir()
            inside = allowed / "photo.jpg"
            inside.write_bytes(b"image")
            outside = base / "secret.txt"
            outside.write_bytes(b"secret")
            symlink = allowed / "escape.txt"
            symlink.symlink_to(outside)
            with patch.object(
                self.server, "ALLOWED_LOCAL_SOURCE_ROOTS", (allowed,)
            ):
                filename, content, _ = self.server._read_binary_source(str(inside))
                self.assertEqual(filename, "photo.jpg")
                self.assertEqual(content, b"image")
                with self.assertRaisesRegex(RuntimeError, "freigegebenen Import-Verzeichnisse"):
                    self.server._read_binary_source(str(outside))
                with self.assertRaisesRegex(RuntimeError, "freigegebenen Import-Verzeichnisse"):
                    self.server._read_binary_source(str(symlink))

    def test_binary_source_blocks_loopback_ssrf_and_oversize_files(self):
        with patch.object(self.server, "ALLOW_REMOTE_SOURCES", True):
            with self.assertRaisesRegex(RuntimeError, "private oder lokale"):
                self.server._read_binary_source("http://127.0.0.1/private.jpg")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "large.bin"
            path.write_bytes(b"1234")
            with (
                patch.object(self.server, "ALLOWED_LOCAL_SOURCE_ROOTS", (Path(tmpdir),)),
                patch.object(self.server, "MAX_SOURCE_BYTES", 3),
            ):
                with self.assertRaisesRegex(RuntimeError, "Größenlimit"):
                    self.server._read_binary_source(str(path))

    def test_multipart_rejects_header_injection_before_network(self):
        with patch.object(self.server.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "Multipart"):
                self.server._multipart_request(
                    "POST",
                    "/api/recipes/create/image",
                    files={"file\r\nX-Evil": ("safe.jpg", b"x", "image/jpeg")},
                    auth=False,
                )
            with self.assertRaisesRegex(RuntimeError, "Multipart"):
                self.server._multipart_request(
                    "POST",
                    "/api/recipes/create/image",
                    files={"file": ("evil\r\nX-Evil.jpg", b"x", "image/jpeg")},
                    auth=False,
                )
        urlopen.assert_not_called()

    def test_raw_ingredient_string_is_part_of_tool_annotation(self):
        annotation = self.server.mealie_update_recipe_ingredients.__annotations__["ingredients"]
        self.assertIn("str", str(annotation))

    def test_parse_ingredients_normalizes_v320_wrapper_response(self):
        ingredient = {
            "quantity": 250.0,
            "unit": {"id": "unit-g", "name": "Gramm"},
            "food": {"id": "food-carrot", "name": "Karotte"},
            "note": "",
            "display": "250 gram Karotten",
        }
        api_result = [
            {
                "input": "250 g Karotten",
                "confidence": {"average": 0.99},
                "ingredient": ingredient,
            }
        ]

        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", return_value=api_result),
        ):
            result = self.server.mealie_parse_ingredients(["250 g Karotten"])

        self.assertEqual(result, {"ingredients": [ingredient], "count": 1})

    def test_recipe_update_preserves_unit_and_food_objects_with_ids(self):
        unit = {"id": "unit-g", "name": "g", "abbreviation": "g"}
        food = {"id": "food-carrot", "name": "Karotten", "description": ""}
        current_recipe = {
            "name": "Testrezept",
            "recipeServings": 2,
            "recipeInstructions": [],
            "tags": [],
            "settings": {},
        }
        patched_body = None

        def fake_request(method, path, *, params=None, body=None, **kwargs):
            nonlocal patched_body
            if method == "GET" and patched_body is None:
                return current_recipe
            if method == "PATCH":
                patched_body = body
                return {"slug": "testrezept"}
            if method == "GET" and patched_body is not None:
                return {"recipeIngredient": patched_body["recipeIngredient"]}
            raise AssertionError(f"Unexpected request: {method} {path}")

        with (
            patch.object(self.server, "_require_mutations"),
            patch.object(self.server, "_json_request", side_effect=fake_request),
        ):
            result = self.server.mealie_update_recipe_ingredients(
                "testrezept",
                [
                    {
                        "quantity": 250,
                        "unit": unit,
                        "food": food,
                        "note": "geraspelt",
                        "display": "250 g Karotten, geraspelt",
                    }
                ],
                confirmed_by_user=True,
            )

        assert patched_body is not None
        ingredient = patched_body["recipeIngredient"][0]
        self.assertEqual(ingredient["unit"], unit)
        self.assertEqual(ingredient["food"], food)
        self.assertEqual(result["parsed_ingredients"], 1)

    def test_ingredient_reference_names_are_resolved_to_objects_with_ids(self):
        unit = {"id": "unit-g", "name": "Gramm", "abbreviation": "g"}
        food = {"id": "food-carrot", "name": "Karotten", "description": ""}

        def fake_request(method, path, *, params=None, **kwargs):
            self.assertEqual(method, "GET")
            if path == "/api/units":
                return {"items": [unit]}
            if path == "/api/foods":
                return {"items": [food]}
            raise AssertionError(f"Unexpected request: {method} {path}")

        with patch.object(self.server, "_json_request", side_effect=fake_request):
            resolved_unit = self.server._resolve_ingredient_reference(
                "g", "/api/units", "Einheit"
            )
            resolved_food = self.server._resolve_ingredient_reference(
                {"name": "Karotten"}, "/api/foods", "Lebensmittel"
            )

        self.assertEqual(resolved_unit, unit)
        self.assertEqual(resolved_food, food)

    def test_persisting_helpers_require_confirmation_before_network(self):
        calls = [
            (self.server.mealie_create_recipe_from_url, ("https://example.com/recipe",)),
            (self.server.mealie_create_shopping_list, ("Groceries",)),
            (
                self.server.mealie_add_shopping_item,
                ("123e4567-e89b-12d3-a456-426614174000", "Milk"),
            ),
            (
                self.server.mealie_update_recipe_ingredients,
                ("test-recipe", ["1 egg"]),
            ),
        ]
        for function, args in calls:
            with self.subTest(function=function.__name__):
                with (
                    patch.object(self.server, "_json_request") as request,
                    patch.object(self.server, "_require_mutations") as mutations,
                ):
                    with self.assertRaisesRegex(RuntimeError, "explizite Bestätigung"):
                        function(*args)
                    request.assert_not_called()
                    mutations.assert_not_called()

    def test_recipe_update_rejects_unknown_fields_before_network(self):
        with (
            patch.object(self.server, "_json_request") as request,
            patch.object(self.server, "_require_mutations") as mutations,
        ):
            with self.assertRaisesRegex(RuntimeError, "Unbekannte Rezept-Update-Felder"):
                self.server.mealie_update_recipe_ingredients(
                    "test-recipe",
                    ["1 egg"],
                    update_fields={"householdId": "forbidden"},
                    confirmed_by_user=True,
                )
            request.assert_not_called()
            mutations.assert_not_called()

    def test_raw_api_resolves_openapi_tags_and_blocks_household_self_service(self):
        sensitive_paths = [
            "/api/households/members",
            "/api/households/preferences",
            "/api/households/permissions",
            "/api/households/self",
            "/api/households/statistics",
        ]
        paths = {
            path: {
                "get": {
                    "operationId": "get_" + path.rsplit("/", 1)[-1],
                    "tags": ["Households: Self Service"],
                }
            }
            for path in sensitive_paths
        }
        with (
            patch.object(self.server, "_get_openapi_spec", return_value={"paths": paths}),
            patch.object(self.server, "_json_request") as request,
        ):
            for path in sensitive_paths:
                with self.subTest(path=path):
                    with self.assertRaisesRegex(RuntimeError, "Sensible"):
                        self.server.mealie_api_get(path)
            request.assert_not_called()

    def test_raw_api_rejects_unknown_paths_fail_closed(self):
        with (
            patch.object(self.server, "_get_openapi_spec", return_value={"paths": {}}),
            patch.object(self.server, "_json_request") as request,
        ):
            with self.assertRaisesRegex(RuntimeError, "OpenAPI"):
                self.server.mealie_api_get("/api/future/unknown")
            request.assert_not_called()

    def test_mealie_redirects_are_rejected_before_forwarding_authorization(self):
        request = self.server.urllib.request.Request(
            "https://mealie.example/api/recipes",
            headers={"Authorization": "Bearer secret"},
        )
        handler = self.server._RejectRedirectHandler()
        with self.assertRaisesRegex(RuntimeError, "Redirect"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://attacker.example/collect",
            )

    def test_base_url_rejects_remote_plain_http_and_embedded_credentials(self):
        self.assertEqual(
            self.server._validate_mealie_base_url("http://127.0.0.1:9000"),
            "http://127.0.0.1:9000",
        )
        self.assertEqual(
            self.server._validate_mealie_base_url("https://mealie.example"),
            "https://mealie.example",
        )
        with self.assertRaisesRegex(RuntimeError, "HTTPS"):
            self.server._validate_mealie_base_url("http://mealie.example")
        with self.assertRaisesRegex(RuntimeError, "Zugangsdaten"):
            self.server._validate_mealie_base_url("https://user:pass@mealie.example")  # pragma: allowlist secret

    def test_recipe_url_import_blocks_non_public_targets_before_mealie_call(self):
        with (
            patch.object(self.server, "_json_request") as request,
            patch.object(self.server, "_require_mutations") as mutations,
            patch.object(self.server, "ALLOW_URL_IMPORTS", True),
        ):
            with self.assertRaisesRegex(RuntimeError, "private oder lokale"):
                self.server.mealie_create_recipe_from_url(
                    "http://127.0.0.1/internal",
                    confirmed_by_user=True,
                )
            request.assert_not_called()
            mutations.assert_not_called()

    def test_remote_sources_and_url_imports_are_disabled_by_default(self):
        with self.assertRaisesRegex(RuntimeError, "Remote-Dateiquellen sind deaktiviert"):
            self.server._read_binary_source("https://example.com/image.jpg")
        with self.assertRaisesRegex(RuntimeError, "URL-Importe sind deaktiviert"):
            self.server.mealie_create_recipe_from_url(
                "https://example.com/recipe",
                confirmed_by_user=True,
            )

    def test_shopping_filter_rejects_injection_before_network(self):
        with patch.object(self.server, "_json_request") as request:
            with self.assertRaisesRegex(RuntimeError, "shopping_list_id"):
                self.server.mealie_list_shopping_items(
                    shopping_list_id='x" OR checked = false OR "x',
                )
            request.assert_not_called()

    def test_bounded_response_reader_rejects_oversized_json(self):
        class Response:
            def read(self, _size):
                return b"x" * 11

        with self.assertRaisesRegex(RuntimeError, "Größenlimit"):
            self.server._read_bounded_response(Response(), 10, "JSON")

    def test_http_error_payload_read_is_bounded(self):
        class Error:
            requested = None

            def read(self, size):
                self.requested = size
                return b"x" * size

        error = Error()
        payload = self.server._read_http_error_payload(error, 32)
        self.assertEqual(error.requested, 33)
        self.assertEqual(len(payload), 32)

    def test_chefkoch_detail_rejects_arbitrary_hosts_before_fetch(self):
        with patch.object(self.server.get_chefkoch, "Recipe") as recipe:
            result = self.server.mealie_get_chefkoch_recipe(
                "https://www.chefkoch.de.attacker.example/rezepte/123/test"
            )
        recipe.assert_not_called()
        self.assertIn("chefkoch.de", result["error"])
        self.assertEqual(
            self.server._validate_chefkoch_recipe_url(
                "https://www.chefkoch.de/rezepte/123/test.html?tracking=1"
            ),
            "https://www.chefkoch.de/rezepte/123/test.html",
        )

    def test_openapi_body_rejects_unknown_fields_fail_closed(self):
        operation = {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}},
                            "required": ["name"],
                        }
                    }
                }
            }
        }
        with self.assertRaisesRegex(RuntimeError, "Unbekannte OpenAPI-Body-Felder"):
            self.server._validate_openapi_request(
                operation,
                query_params=None,
                body={"name": "safe", "householdId": "forbidden"},
                content_type="application/json",
            )

    def test_ocr_output_is_capped(self):
        oversized = "x" * (self.server.MAX_OCR_TEXT_CHARS + 10)
        with (
            patch.object(self.server, "_preprocess_for_ocr", return_value=object()),
            patch.object(
                self.server.pytesseract,
                "image_to_string",
                return_value=oversized,
            ),
            patch.object(
                self.server.pytesseract,
                "image_to_data",
                return_value={"conf": [], "text": []},
            ),
        ):
            result = self.server._ocr_extract_text(b"ignored")
        self.assertEqual(len(result["raw_text"]), self.server.MAX_OCR_TEXT_CHARS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
