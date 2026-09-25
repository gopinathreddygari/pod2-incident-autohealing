"""Deterministic IaC recovery-script drafts, one template per remediation action.

The planner shows these next to the executable kubectl command so an SRE can
review (or commit to Git) the declarative equivalent of the fix:

* ``kubernetes-yaml``  apply_hotfix, scale_deployment, rollback_deployment
* ``ansible-yaml``     restart_service, clear_pod_cache, drain_node
* ``terraform-hcl``    failover_cluster

Drafts are **never executed**. Only the kubectl command goes through the MCP
tool server. Values come from the code-bound tool arguments (themselves
bound from ``incident.target``), never from model text. ``string.Template``
(``$var``) is used rather than ``str.format`` so HCL/YAML braces stay literal
and no ``${...}`` survives rendering, which the script guardrail would reject.
"""

from __future__ import annotations

from string import Template
from typing import Any

from mcp_server.tool_server import HOTFIX_CATALOG

SCRIPT_TEMPLATES: dict[str, tuple[str, str]] = {
    "apply_hotfix": ("kubernetes-yaml", """\
# Recovery draft for $incident_id (not executed): vetted catalog patch hotfixes/$patch.yaml
# Catalog entry: $patch_description
# Applied with: kubectl patch deployment/$deployment -n $namespace --type=strategic --patch-file=hotfixes/$patch.yaml
$patch_content"""),
    "scale_deployment": ("kubernetes-yaml", """\
# Recovery draft for $incident_id (not executed): scale deployment/$deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $deployment
  namespace: $namespace
  annotations:
    kubernetes.io/change-cause: "scaled to $replicas replicas by incident-platform ($incident_id)"
spec:
  replicas: $replicas
"""),
    "rollback_deployment": ("kubernetes-yaml", """\
# Recovery draft for $incident_id (not executed): the declarative equivalent of
# "rollout undo" is to re-apply the previous known-good revision of deployment/$deployment from Git.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $deployment
  namespace: $namespace
  annotations:
    kubernetes.io/change-cause: "rollback to previous revision by incident-platform ($incident_id)"
"""),
    "restart_service": ("ansible-yaml", """\
# Recovery draft for $incident_id (not executed)
- name: Rolling restart of $workload
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Bump the restart annotation on deployment/$workload
      kubernetes.core.k8s:
        state: patched
        kind: Deployment
        name: $workload
        namespace: $namespace
        definition:
          spec:
            template:
              metadata:
                annotations:
                  kubectl.kubernetes.io/restartedAt: "$incident_id"
"""),
    "clear_pod_cache": ("ansible-yaml", """\
# Recovery draft for $incident_id (not executed)
- name: Flush in-memory caches of $workload
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Set the cache-flush annotation on deployment/$workload
      kubernetes.core.k8s:
        state: patched
        kind: Deployment
        name: $workload
        namespace: $namespace
        definition:
          metadata:
            annotations:
              cache.cloudscale.io/flush: "now"
"""),
    "drain_node": ("ansible-yaml", """\
# Recovery draft for $incident_id (not executed)
- name: Cordon and drain $node
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Drain node $node
      kubernetes.core.k8s_drain:
        name: $node
        state: drain
        delete_options:
          ignore_daemonsets: true
          delete_emptydir_data: true
"""),
    "failover_cluster": ("terraform-hcl", """\
# Recovery draft for $incident_id (not executed): fail region $region over to standby
resource "aws_route53_record" "api_$region_slug" {
  zone_id        = var.public_zone_id
  name           = "api.$region.cloudscale.example"
  type           = "CNAME"
  ttl            = 30
  set_identifier = "$region-standby"
  records        = ["standby.$region.cloudscale.example"]

  failover_routing_policy {
    type = "PRIMARY"
  }
}
"""),
}


def render_script(action: str, arguments: dict[str, Any], incident_id: str) -> tuple[str, str]:
    """Return (format, draft) for a remediation action; ("", "") if it has no template."""
    if action not in SCRIPT_TEMPLATES:
        return "", ""
    fmt, template = SCRIPT_TEMPLATES[action]
    values = {k: str(v) for k, v in arguments.items()}
    values["incident_id"] = incident_id
    if "region" in values:
        values["region_slug"] = values["region"].replace("-", "_")
    if action == "apply_hotfix":
        entry = HOTFIX_CATALOG.get(values.get("patch", ""))
        values["patch_description"] = entry["description"] if entry else "NOT IN THE VETTED CATALOG (will be refused)"
        values["patch_content"] = entry["patch"] if entry else "# no patch content: unknown id\n"
    return fmt, Template(template).substitute(values)
