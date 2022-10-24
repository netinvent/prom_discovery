"""
Write <file_sd_config> files as json

[ {
        "targets": [ "myslave1:9104", "myslave2:9104" ],
        "labels": {
          "env": "prod",
          "job": "mysql_slave"
        }
    },
    {
      "targets": [ "mymaster:9104" ],
        "labels": {
          "env": "prod",
          "job": "mysql_master"
        }
    },
      {
        "targets": [ "mymaster:9100", "myslave1:9100", "myslave2:9100" ],
            "labels": {
              "env": "prod",
              "job": "node"
            }
    }
]
"""

from typing import List
import json
import os


class FileSDConfig:
    def __init__(self, filename: str):
        self.filename = filename
        self.read()

    def read(self) -> dict:
        if os.path.isfile(self.filename):
            with open(self.filename, "r") as file:
                self.sd_config = json.loads(file.read())
        else:
            self.sd_config = [
                {
                    "targets" : [],
                    "labels" : "",
                    "job": "" # We need a default job if not created
                }
            ]

    def save(self) -> bool:
        with open(self.filename, "w") as file:
            file.write(json.dumps(self.sd_config, indent=4))


    def get_targets_from_sd_config(self, job: str) -> List[str]:
        for target_list in self.sd_config:
            if target_list["labels"]["job"] == job:
                return target_list["targets"]


    def add_target_to_sd_config(self, target: str, job: str) -> dict:
        for index, target_list in enumerate(self.sd_config):
            if target_list["labels"]["job"] == job:
                if target not in self.sd_config[index]["targets"]:
                    self.sd_config[index]["targets"].append(target)

    def remove_target_from_sd_config(self, target: str, job: str) -> dict:
        for index, target_list in enumerate(self.sd_config):
            if target_list["labels"]["job"] == job:
                self.sd_config[index]["targets"].remove(target)


test = FileSDConfig("config.json")
print(test.get_targets_from_sd_config("node"))
test.add_target_to_sd_config("toto", "node")
print(test.get_targets_from_sd_config("node"))
test.remove_target_from_sd_config("toto", "node")
print(test.get_targets_from_sd_config("node"))
test.save()