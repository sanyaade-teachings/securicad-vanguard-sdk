# Copyright 2020-2021 Foreseeti AB <https://foreseeti.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import base64
import json
import math
import re
import sys
import time
from collections import defaultdict
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin

import boto3
import botocore
import requests
from botocore.config import Config
from bs4 import BeautifulSoup
from bs4.element import Tag
from pycognito.aws_srp import AWSSRP  # type: ignore
from securicad.model import Model, Object, es_serializer

from securicad.vanguard.exceptions import (
    AwsCredentialsError,
    AwsRegionError,
    RateLimitError,
    StatusCodeException,
    VanguardCredentialsError,
)

if TYPE_CHECKING:
    from mypy_boto3_cognito_idp.type_defs import RespondToAuthChallengeResponseTypeDef


class Profile(Enum):
    STATESPONSORED = "State-sponsored"
    CYBERCRIMINAL = "Cybercriminal"
    OPPORTUNIST = "Opportunist"


class Client:
    def __init__(
        self,
        username: str,
        password: str,
        url: str = "https://vanguard.securicad.com",
        region: str = "eu-central-1",
    ):
        self.__init_urls(url)
        self.__init_session()

        self.__login(username, password, region)

    def __init_urls(self, url: str) -> None:
        self._base_url = urljoin(url, "/")
        self._backend_url = urljoin(url, "/backend/")

    def __init_session(self) -> None:
        def get_user_agent() -> str:
            # pylint: disable=import-outside-toplevel
            import securicad.vanguard

            return f"Vanguard SDK {securicad.vanguard.__version__}"

        self._session = requests.Session()
        self._session.headers["User-Agent"] = get_user_agent()

    def _get_access_token(self) -> Optional[str]:
        if "Authorization" not in self._session.headers:
            return None
        return self._session.headers["Authorization"][len("JWT ") :]

    def _set_access_token(self, access_token: Optional[str]) -> None:
        if access_token is None:
            if "Authorization" in self._session.headers:
                del self._session.headers["Authorization"]
        else:
            self._session.headers["Authorization"] = f"JWT {access_token}"

    def __request(self, method: str, endpoint: str, data: Any, status_code: int) -> Any:
        url = urljoin(self._backend_url, endpoint)
        response = self._session.request(method, url, json=data)
        if response.status_code != status_code:
            raise StatusCodeException(status_code, method, url, response)
        return response.json()["response"]

    def _get(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("GET", endpoint, data, status_code)

    def _post(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("POST", endpoint, data, status_code)

    def _put(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("PUT", endpoint, data, status_code)

    def _delete(self, endpoint: str, data: Any = None, status_code: int = 200) -> Any:
        return self.__request("DELETE", endpoint, data, status_code)

    def __login(self, username: str, password: str, region: str) -> None:
        access_token = self.__authenticate(username, password, region)
        self._set_access_token(access_token)
        self._get("whoami")

    def __authenticate(self, username: str, password: str, region: str) -> str:
        def get_cognito_params() -> tuple[str, str]:
            bundle = get_bundle()
            pattern = re.compile(
                fr"{{\s*UserPoolId:\s*['\"]({region}[^'\"]+)['\"],\s*ClientId:\s*['\"]([^'\"]+)['\"]\s*}}"
            )
            match = pattern.search(bundle)
            if match:
                userpool_id = str(match.group(1))
                client_id = str(match.group(2))
                return client_id, userpool_id
            raise EnvironmentError("Failed to get cognito parameters")

        def get_bundle() -> str:
            bundle_name = get_bundle_name()
            response = requests.get(urljoin(self._base_url, bundle_name))
            response.raise_for_status()
            return response.text

        def get_bundle_name() -> str:
            index_html = get_index_html()
            soup = BeautifulSoup(index_html, "html.parser")
            pattern = re.compile(r"/main\.[0-9a-f]+\.js")
            for tag in soup.find_all("script"):
                if not isinstance(tag, Tag):
                    continue
                if "src" not in tag.attrs:
                    continue
                if (
                    pattern.fullmatch(tag.attrs["src"])
                    or tag.attrs["src"] == "/bundle.js"
                ):
                    return tag.attrs["src"]
            raise EnvironmentError("Failed to get bundle name")

        def get_index_html() -> str:
            response = requests.get(urljoin(self._base_url, "index.html"))
            response.raise_for_status()
            return response.text

        client = boto3.client(
            "cognito-idp",
            region_name=region,
            config=Config(signature_version=botocore.UNSIGNED),
        )
        client_id, pool_id = get_cognito_params()
        aws = AWSSRP(
            username=username,
            password=password,
            pool_id=pool_id,
            client_id=client_id,
            client=client,
        )
        try:
            tokens: RespondToAuthChallengeResponseTypeDef = aws.authenticate_user()
            return tokens["AuthenticationResult"]["AccessToken"]
        except Exception as ex:
            raise VanguardCredentialsError("Invalid password or username") from ex

    def get_model(
        self,
        *,
        data: Optional[dict[str, Any]] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: Optional[str] = None,
        include_inspector: bool = False,
        vuln_data: Optional[dict[str, Any]] = None,
    ) -> Model:
        try:
            if data is not None:
                model_tag = self.__build_from_config(data, vuln_data)
            elif (
                access_key is not None and secret_key is not None and region is not None
            ):
                model_tag = self.__build_from_role(
                    access_key, secret_key, region, include_inspector, vuln_data
                )
            else:
                raise ValueError(
                    "Either data or access_key, secret_key, and region must be specified"
                )
        except StatusCodeException as ex:
            if ex.status_code == 429:
                raise RateLimitError(
                    "You are currently ratelimited, please wait for other models to complete"
                ) from ex
            raise

        try:
            model = self.__wait_for_model(model_tag)
        except StatusCodeException as ex:
            if ex.status_code == 400 and ex.json is not None:
                error_message = ex.json["error"]

                # Credentials error
                credentials_error = "No valid AWS credentials found"
                if error_message == credentials_error:
                    raise AwsCredentialsError(error_message) from ex

                # Region error
                region_error = "No valid AWS Region found"
                if error_message == region_error:
                    raise AwsRegionError(error_message) from ex

            raise

        return es_serializer.deserialize_model(model)

    def __build_from_config(
        self, aws_data: dict[str, Any], vuln_data: Optional[dict[str, Any]]
    ) -> str:
        def get_file_content(dict_file: dict[str, Any]) -> str:
            file_str = json.dumps(dict_file, allow_nan=False, indent=2)
            file_bytes = file_str.encode("utf-8")
            file_base64 = base64.b64encode(file_bytes).decode("utf-8")
            return file_base64

        def get_file(name: str, dict_file: dict[str, Any]) -> dict[str, Any]:
            return {
                "filename": name,
                "content": get_file_content(dict_file),
            }

        data: dict[str, Any] = {"files": [get_file("apimodel.json", aws_data)]}
        if vuln_data is not None:
            data["additionalFiles"] = [get_file("vulnerabilities.json", vuln_data)]
        response = self._put("build_from_config", data, 202)
        model_tag: str = response["mtag"]
        return model_tag

    def __build_from_role(
        self,
        access_key: str,
        secret_key: str,
        region: str,
        include_inspector: bool,
        vuln_data: Optional[dict[str, Any]],
    ) -> str:
        def get_file_content(dict_file: dict[str, Any]) -> str:
            file_str = json.dumps(dict_file, allow_nan=False, indent=2)
            file_bytes = file_str.encode("utf-8")
            file_base64 = base64.b64encode(file_bytes).decode("utf-8")
            return file_base64

        def get_file(name: str, dict_file: dict[str, Any]) -> dict[str, Any]:
            return {
                "filename": name,
                "content": get_file_content(dict_file),
            }

        data: dict[str, Any] = {
            "access_key": access_key,
            "secret_key": secret_key,
            "region": region,
            "include_inspector": include_inspector,
        }
        if vuln_data is not None:
            data["additionalFiles"] = [get_file("vulnerabilities.json", vuln_data)]
        response = self._put("build_from_role", data, 202)
        model_tag: str = response["mtag"]
        return model_tag

    def __wait_for_model(self, model_tag: str) -> dict[str, Any]:
        while True:
            try:
                response: dict[str, Any] = self._post("get_model", {"mtag": model_tag})
                return response
            except StatusCodeException as ex:
                if ex.status_code != 204:
                    raise
                time.sleep(5)

    @staticmethod
    def set_high_value_assets(
        model: Model,
        instances: Optional[list[str]] = None,
        dbinstances: Optional[list[str]] = None,
        buckets: Optional[list[str]] = None,
        dynamodb_tables: Optional[list[str]] = None,
        high_value_assets: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        def get_hva_list() -> list[dict[str, Any]]:
            def create_hva_tag(
                metaconcept: str, attackstep: str, key: str, value: str
            ) -> dict[str, Any]:
                return {
                    "metaconcept": metaconcept,
                    "attackstep": attackstep,
                    "id": {
                        "type": "tag",
                        "key": key,
                        "value": value,
                    },
                }

            def create_hva_name(
                metaconcept: str, attackstep: str, name: str
            ) -> dict[str, Any]:
                return {
                    "metaconcept": metaconcept,
                    "attackstep": attackstep,
                    "id": {
                        "type": "name",
                        "value": name,
                    },
                }

            hva_list: list[dict[str, Any]] = []

            if instances:
                for identifier in instances:
                    hva_list.append(
                        create_hva_tag(
                            metaconcept="EC2Instance",
                            attackstep="HighPrivilegeAccess",
                            key="aws-id",
                            value=identifier,
                        )
                    )

            if dbinstances:
                for identifier in dbinstances:
                    hva_list.append(
                        create_hva_name(
                            metaconcept="DBInstance",
                            attackstep="ReadDatabase",
                            name=identifier,
                        )
                    )

            if buckets:
                for identifier in buckets:
                    hva_list.append(
                        create_hva_name(
                            metaconcept="S3Bucket",
                            attackstep="ReadObject",
                            name=identifier,
                        )
                    )

            if dynamodb_tables:
                for identifier in dynamodb_tables:
                    hva_list.append(
                        create_hva_name(
                            metaconcept="DynamoDBTable",
                            attackstep="AuthenticatedRead",
                            name=identifier,
                        )
                    )

            if high_value_assets:
                hva_list.extend(high_value_assets)

            return hva_list

        def is_hva(obj: Object, hv_asset: dict[str, Any]) -> bool:
            # Check if a model object matches any of the high value assets
            if not hv_asset.get("id"):
                return True
            if hv_asset["id"]["type"] == "name":
                name: str = hv_asset["id"]["value"]
                return obj.name == name
            if hv_asset["id"]["type"] == "tag":
                key: str = hv_asset["id"]["key"]
                value: str = hv_asset["id"]["value"]
                tag = obj.meta["tags"].get(key)
                return isinstance(tag, str) and tag == value
            return False

        hva_list = get_hva_list()

        # Collect the high value assets under their metaconcept
        hv_assets: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for hv_asset in hva_list:
            hv_assets[hv_asset["metaconcept"]].append(hv_asset)

        # Check if any of the objects are eligible as a high value asset
        for obj in model.objects():
            if obj.asset_type not in hv_assets:
                continue
            for hv_asset in hv_assets[obj.asset_type]:
                if not is_hva(obj, hv_asset):
                    continue
                if hv_asset.get("consequence") is not None:
                    consequence: int = hv_asset["consequence"]
                else:
                    consequence = 10
                attackstep = obj.attack_step(hv_asset["attackstep"])
                attackstep.meta["consequence"] = consequence

    def simulate(
        self, model: Model, profile: Profile, export_report: bool = False
    ) -> dict[str, Any]:
        def has_high_value_asset(model: Model) -> bool:
            for obj in model.objects():
                for step in obj._attack_steps.values():
                    meta: dict[str, Any] = step.meta
                    if meta.get("consequence", 0):
                        return True
            return False

        if not has_high_value_asset(model):
            raise ValueError("Model must have at least one high value asset")

        try:
            simulation_tag = self.__simulate_model(
                es_serializer.serialize_model(model), profile.value
            )
        except StatusCodeException as ex:
            if ex.status_code == 429:
                raise RateLimitError(
                    "You are currently ratelimited, please wait for other simulations to complete"
                ) from ex
            raise

        results = self.__wait_for_results(simulation_tag)
        parsed_results = self.__parse_results(results)
        if export_report:
            parsed_results["Report"] = results
        return parsed_results

    def __simulate_model(self, model: dict[str, Any], profile: str) -> str:
        model["name"] = "vanguard_model"
        data = {"model": model, "profile": profile, "demo": False}
        response = self._put("simulate", data)
        simulation_tag: str = response["tag"]
        return simulation_tag

    def __wait_for_results(self, simulation_tag: str) -> dict[str, Any]:
        while True:
            try:
                response: dict[str, Any] = self._post(
                    "results", {"tag": simulation_tag}
                )
                return response
            except StatusCodeException as ex:
                if ex.status_code != 204:
                    raise
                time.sleep(5)

    @staticmethod
    def __parse_results(results: dict[str, Any]) -> dict[str, Any]:
        def get_key(data: dict[str, Any]) -> str:
            object_id = int(data["object_id"])
            for obj in model["objects"].values():
                if obj["eid"] == object_id:
                    if "aws-id" in obj["tags"] and obj["tags"]["aws-id"]:
                        return str(obj["tags"]["aws-id"])
                    if obj["name"]:
                        return str(obj["name"])
                    if "Name" in obj["tags"] and obj["tags"]["Name"]:
                        return str(obj["tags"]["Name"])
                    return str(obj["eid"])
            return str(object_id)

        model = results["model_data"]
        parsed_results: dict[str, Any] = {}
        for data in results["results"]["data"].values():
            metaconcept = data["metaconcept"]
            attackstep = data["attackstep"]
            object_name = data["object_name"]
            consequence = int(data["consequence"])
            probability = float(data["probability"])
            ttc50 = float(data["ttc50"])
            if ttc50 == sys.float_info.max:
                ttc50 = math.inf
            else:
                ttc50 = int(ttc50)

            result = {
                "metaconcept": metaconcept,
                "attackstep": attackstep,
                "name": object_name,
                "consequence": consequence,
                "probability": probability,
                "ttc": ttc50,
            }

            if metaconcept not in parsed_results:
                parsed_results[metaconcept] = {}
            parsed_results[metaconcept][get_key(data)] = result
        return parsed_results
