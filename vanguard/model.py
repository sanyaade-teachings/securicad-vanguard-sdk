# Copyright 2020 Foreseeti AB
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


class Model:
    def __init__(self, model):
        self.model = model
        self.result_map = {}

    def set_high_value_assets(self, **kwargs):
        instances = kwargs.get("instances", [])
        buckets = kwargs.get("buckets", [])
        dbinstances = kwargs.get("dbinstances", [])
        for index, obj in enumerate(self.model["objects"]):
            if obj["metaconcept"] == "S3Bucket":
                self.high_value_bucket(obj, index, buckets)
            elif obj["metaconcept"] == "DBInstance":
                self.high_value_dbinstance(obj, index, dbinstances)
            elif obj["metaconcept"] == "EC2Instance":
                self.high_value_instance(obj, index, instances)

    def high_value_instance(self, obj, index, instance_ids):
        attackstep = "HighPrivilegeAccess"
        instance_id = self.get_tag(obj, "aws-id")
        if instance_id in instance_ids:
            ev = self.evidence(attackstep)
            self.model["objects"][index]["attacksteps"] = ev
            self.result_map[self.result_key(obj, attackstep)] = instance_id

    def high_value_dbinstance(self, obj, index, dbinstances):
        attackstep = "ReadDatabase"
        if obj["name"] in dbinstances:
            ev = self.evidence(attackstep)
            self.model["objects"][index]["attacksteps"] = ev
            self.result_map[self.result_key(obj, attackstep)] = obj["name"]

    def high_value_bucket(self, obj, index, buckets):
        attackstep = "ReadObject"
        if obj["name"] in buckets:
            ev = self.evidence(attackstep)
            self.model["objects"][index]["attacksteps"] = ev
            self.result_map[self.result_key(obj, attackstep)] = obj["name"]

    def evidence(self, attackstep, evidence=10):
        evidence_dict = {
            attackstep: {
                "evidence": evidence,
                "name": attackstep,
                "distribution": "securiCAD default",
                "distribution_params": {},
            }
        }
        return evidence_dict

    def result_key(self, obj, attackstep):
        return f"{obj['id']}.{attackstep}"

    def get_tag(self, obj, key):
        tags = obj.get("tags")
        for tag in tags:
            if tag["key"] == key:
                return tag["value"]
